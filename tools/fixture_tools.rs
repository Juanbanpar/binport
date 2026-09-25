//! Development-only fixture mutations, manifest generation and fuzz seeding.
//! Artifacts are always data. Only sha256sum is invoked, for hashing stdin.
use elf::{ElfBytes, abi, endian::AnyEndian, section::SectionHeader};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Serialize, Deserialize)]
struct Entry {
    sha256: String,
    bytes: usize,
}

fn sha256(data: &[u8]) -> Result<String> {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let write = child
        .stdin
        .take()
        .ok_or("missing hash stdin")?
        .write_all(data);
    let output = child.wait_with_output()?;
    write?;
    if !output.status.success() {
        return Err("sha256sum failed".into());
    }
    let output = String::from_utf8(output.stdout)?;
    let hash = output.split_whitespace().next().ok_or("missing digest")?;
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid SHA-256 output".into());
    }
    Ok(hash.to_owned())
}

fn write_data(path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
    fs::write(&path, data)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

fn manifest(root: &Path) -> Result<()> {
    let mut entries = BTreeMap::new();
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_file() && path.extension().is_none() && path.file_name().unwrap() != "README" {
            let data = fs::read(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
            entries.insert(
                path.file_name()
                    .unwrap()
                    .to_str()
                    .ok_or("non-UTF-8 fixture name")?
                    .to_owned(),
                Entry {
                    sha256: sha256(&data)?,
                    bytes: data.len(),
                },
            );
        }
    }
    fs::write(
        root.join("manifest.json"),
        format!("{}\n", serde_json::to_string_pretty(&entries)?),
    )?;
    Ok(())
}

fn seed(fixtures: &Path, destination: &Path) -> Result<()> {
    let entries: BTreeMap<String, Entry> =
        serde_json::from_slice(&fs::read(fixtures.join("manifest.json"))?)?;
    let mut seeds = Vec::new();
    // Verify the entire manifest before writing any seeds. Do not remove inputs
    // found by prior fuzz runs, or copy source files and license notices.
    for (name, expected) in entries {
        let mut components = Path::new(&name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(format!("invalid fixture name: {name}").into());
        }
        let data = fs::read(fixtures.join(&name))?;
        if data.len() != expected.bytes || sha256(&data)? != expected.sha256 {
            return Err(format!("fixture differs from manifest: {name}").into());
        }
        seeds.push((name, data));
    }
    fs::create_dir_all(destination)?;
    for (name, data) in &seeds {
        write_data(destination.join(name), data)?;
    }
    println!(
        "Seeded {} verified fixtures into {}",
        seeds.len(),
        destination.display()
    );
    Ok(())
}

// Fixed offsets below mutate controlled ELF64 little-endian fixtures only.
// Section and segment headers themselves are parsed by the elf crate.
fn sections(data: &[u8]) -> Result<Vec<SectionHeader>> {
    let elf = ElfBytes::<AnyEndian>::minimal_parse(data)?;
    if elf.ehdr.class != elf::file::Class::ELF64 || data[5] != abi::ELFDATA2LSB {
        return Err("mutation requires ELF64 little-endian".into());
    }
    Ok(elf
        .section_headers()
        .ok_or("missing sections")?
        .iter()
        .collect())
}

fn u16_at(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}
fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn weak_version(original: &[u8], weak: bool) -> Result<Vec<u8>> {
    let mut data = original.to_vec();
    let headers = sections(&data)?;
    let mut changed = 0;
    for section in &headers {
        if section.sh_type != abi::SHT_GNU_VERNEED {
            continue;
        }
        let strings = &headers[section.sh_link as usize];
        let mut need = section.sh_offset as usize;
        for _ in 0..section.sh_info {
            let mut aux = need + u32_at(&data, need + 8) as usize;
            for _ in 0..u16_at(&data, need + 2) {
                let name = strings.sh_offset as usize + u32_at(&data, aux + 8) as usize;
                if data[name..].split(|b| *b == 0).next() == Some(b"GLIBC_2.39") {
                    let flags = u16_at(&data, aux + 4);
                    let flags = if weak {
                        flags | abi::VER_FLG_WEAK
                    } else {
                        flags & !abi::VER_FLG_WEAK
                    };
                    data[aux + 4..aux + 6].copy_from_slice(&flags.to_le_bytes());
                    changed += 1;
                }
                aux += u32_at(&data, aux + 12) as usize;
            }
            need += u32_at(&data, need + 12) as usize;
        }
    }
    if changed != 1 {
        return Err("expected exactly one GLIBC_2.39 requirement".into());
    }
    Ok(data)
}

fn mutate(root: &Path, weak_input: &Path) -> Result<()> {
    let mut invalid_abi = fs::read(root.join("glibc-old-shared"))?;
    invalid_abi[8] = 255;
    write_data(root.join("abi-version-invalid"), &invalid_abi)?;
    invalid_abi[7..9].copy_from_slice(&[3, 1]);
    write_data(root.join("abi-version-gnu"), &invalid_abi)?;
    let weak = fs::read(weak_input)?;
    write_data(
        root.join("weak-symbol-hard-version"),
        &weak_version(&weak, false)?,
    )?;
    write_data(root.join("weak-version"), &weak_version(&weak, true)?)?;

    let new = fs::read(root.join("glibc-new"))?;
    let headers = sections(&new)?;
    let mut sectionless = new.clone();
    sectionless[40..48].fill(0);
    sectionless[58..64].fill(0);
    write_data(root.join("sectionless"), &sectionless)?;
    write_data(root.join("non-elf"), b"not an ELF artifact\n")?;
    write_data(root.join("truncated-elf"), &new[..32])?;
    let mut broken = new.clone();
    broken[40..48].fill(255);
    write_data(root.join("malformed-elf"), &broken)?;
    let mut hidden = new.clone();
    let mut bad_index = new.clone();
    let mut bad_need = new;
    for section in headers {
        let start = section.sh_offset as usize;
        if section.sh_type == abi::SHT_GNU_VERSYM {
            for offset in (start..start + section.sh_size as usize).step_by(2) {
                let index = u16_at(&hidden, offset);
                if index > 1 {
                    hidden[offset..offset + 2].copy_from_slice(&(index | 0x8000).to_le_bytes());
                    bad_index[offset..offset + 2].copy_from_slice(&0x7ffe_u16.to_le_bytes());
                }
            }
        }
        if section.sh_type == abi::SHT_GNU_VERNEED {
            bad_need[start..start + 2].fill(255);
        }
    }
    write_data(root.join("hidden-version-index"), &hidden)?;
    write_data(root.join("bad-version-index"), &bad_index)?;
    write_data(root.join("bad-verneed"), &bad_need)?;

    let mut padded = fs::read(root.join("glibc-old"))?;
    let elf = ElfBytes::<AnyEndian>::minimal_parse(&padded)?;
    let (index, segment) = elf
        .segments()
        .ok_or("missing segments")?
        .iter()
        .enumerate()
        .find(|(_, p)| p.p_type == abi::PT_INTERP)
        .ok_or("missing interpreter")?;
    let header = elf.ehdr.e_phoff as usize + index * usize::from(elf.ehdr.e_phentsize);
    if padded[(segment.p_offset + segment.p_filesz) as usize] != 0 {
        return Err("no interpreter padding byte".into());
    }
    padded[header + 32..header + 40].copy_from_slice(&(segment.p_filesz + 1).to_le_bytes());
    padded[header + 40..header + 48].copy_from_slice(&(segment.p_memsz + 1).to_le_bytes());
    write_data(root.join("padded-interpreter"), &padded)?;
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let project = Path::new(env!("CARGO_MANIFEST_DIR"));
    match args.as_slice() {
        [command] if command == "seed-corpus" => seed(
            &project.join("tests/fixtures"),
            &project.join("fuzz/corpus/analyze_bytes"),
        ),
        [command, destination] if command == "seed-corpus" => {
            seed(&project.join("tests/fixtures"), &PathBuf::from(destination))
        }
        [command, root] if command == "manifest" => manifest(&PathBuf::from(root)),
        [command, root, weak] if command == "mutate" => {
            mutate(&PathBuf::from(root), &PathBuf::from(weak))
        }
        _ => Err(
            "usage: fixture-tools seed-corpus [DEST] | manifest DIR | mutate DIR WEAK_INPUT".into(),
        ),
    }
}

fn main() -> io::Result<()> {
    run().map_err(|error| io::Error::other(error.to_string()))
}
