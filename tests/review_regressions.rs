use binport::{analyze, analyze_bytes, compat, model::*, report};
use elf::{ElfBytes, abi, endian::AnyEndian};
use std::{path::PathBuf, process::Command};

const DT_AUXILIARY: i64 = 0x7fff_fffd;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn distro(id: &str) -> compat::distro::DistroRelease {
    compat::distro::built_in()
        .unwrap()
        .into_iter()
        .find(|d| d.id == id)
        .unwrap()
}

fn inspection(name: &str) -> Inspection {
    let binary = analyze(fixture(name)).unwrap();
    let compatibility = vec![compat::evaluate(&binary, &distro("debian-12"), None)];
    Inspection {
        schema_version: 1,
        binary,
        compatibility,
    }
}

#[test]
fn abi_version_is_retained_and_invalid_sysv_dsos_fail() {
    let normal = inspection("glibc-old-shared");
    assert_eq!(normal.binary.abi_version, 0);
    assert_eq!(normal.compatibility[0].status, Compatibility::Compatible);

    let invalid = inspection("abi-version-invalid");
    assert_eq!(invalid.binary.binary_type, BinaryType::SharedLibrary);
    assert_eq!(invalid.binary.os_abi, 0);
    assert_eq!(invalid.binary.abi_version, 255);
    assert_eq!(invalid.compatibility[0].status, Compatibility::Incompatible);
    let constraint = invalid.compatibility[0]
        .constraints
        .iter()
        .find(|c| c.constraint == "abi_version")
        .unwrap();
    assert!(constraint.reason.contains("requires version 0"));
    let json: serde_json::Value =
        serde_json::from_str(&report::json::render(&invalid).unwrap()).unwrap();
    assert_eq!(json["binary"]["abi_version"], 255);
    assert!(report::text::render(&invalid).contains("ABI version: 255"));
}

#[test]
fn unmodeled_gnu_abi_extensions_are_unknown_not_rejected_as_sysv() {
    let unknown = inspection("abi-version-gnu");
    assert_eq!(unknown.binary.os_abi, 3);
    assert_eq!(unknown.binary.abi_version, 1);
    assert_eq!(unknown.compatibility[0].status, Compatibility::Unknown);
    // Executables may be mapped directly by the kernel: do not claim the DSO
    // rejection rule applies to them, but do not claim a supported ABI either.
    let mut data = std::fs::read(fixture("glibc-old")).unwrap();
    data[8] = 255;
    let binary = analyze_bytes("executable ABI extension", &data).unwrap();
    assert_eq!(
        compat::evaluate(&binary, &distro("debian-12"), None).status,
        Compatibility::Unknown
    );
}

#[test]
fn weak_versions_do_not_raise_the_mandatory_floor() {
    let inspection = inspection("weak-version");
    let binary = &inspection.binary;
    let minimum = binary.glibc_requirement.as_ref().unwrap();
    assert_eq!(minimum.minimum.to_string(), "2.17");
    assert_eq!(minimum.causing_symbols, ["clock_gettime"]);
    let optional = binary
        .version_requirements
        .iter()
        .find(|r| r.version == "GLIBC_2.39")
        .unwrap();
    assert!(optional.weak);
    assert_eq!(optional.symbols, ["pidfd_spawnp"]);
    assert_eq!(inspection.compatibility[0].status, Compatibility::Unknown);
    let glibc = inspection.compatibility[0]
        .constraints
        .iter()
        .find(|c| c.constraint == "glibc")
        .unwrap();
    assert!(glibc.reason.contains("weak version requirements"));
    assert_eq!(glibc.causing_symbols, ["pidfd_spawnp@GLIBC_2.39"]);
    assert_eq!(
        compat::evaluate_glibc(binary, "2.39".parse().unwrap()).status,
        Compatibility::Compatible
    );

    // An optional requirement cannot hide a proven hard incompatibility.
    let too_old = compat::evaluate_glibc(binary, "2.16".parse().unwrap());
    assert_eq!(too_old.status, Compatibility::Incompatible);
    assert_eq!(
        too_old.constraints[0].causing_symbols,
        ["clock_gettime@GLIBC_2.17"]
    );

    let json: serde_json::Value =
        serde_json::from_str(&report::json::render(&inspection).unwrap()).unwrap();
    let optional_json = json["binary"]["version_requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["version"] == "GLIBC_2.39")
        .unwrap();
    assert_eq!(optional_json["weak"], true);
    assert!(report::text::render(&inspection).contains("GLIBC_2.39 (weak version)"));
    let roundtrip: Inspection = serde_json::from_value(json).unwrap();
    assert_eq!(
        roundtrip.binary.version_requirements,
        binary.version_requirements
    );
}

#[test]
fn weak_symbols_with_mandatory_version_records_still_raise_the_floor() {
    let binary = analyze(fixture("weak-symbol-hard-version")).unwrap();
    assert_eq!(
        binary
            .glibc_requirement
            .as_ref()
            .unwrap()
            .minimum
            .to_string(),
        "2.39"
    );
    assert!(
        !binary
            .version_requirements
            .iter()
            .find(|r| r.version == "GLIBC_2.39")
            .unwrap()
            .weak
    );
    assert_eq!(
        compat::evaluate(&binary, &distro("debian-12"), None).status,
        Compatibility::Incompatible
    );

    // Prove that the difference is VER_FLG_WEAK, not a different symbol binding.
    for name in ["weak-version", "weak-symbol-hard-version"] {
        let data = std::fs::read(fixture(name)).unwrap();
        let elf = ElfBytes::<AnyEndian>::minimal_parse(&data).unwrap();
        let (symbols, strings) = elf.dynamic_symbol_table().unwrap().unwrap();
        let optional = symbols
            .iter()
            .find(|s| strings.get(s.st_name as usize).unwrap() == "pidfd_spawnp")
            .unwrap();
        assert!(optional.is_undefined());
        assert_eq!(optional.st_bind(), abi::STB_WEAK);
    }
}

#[test]
fn weak_nonnumeric_versions_remain_visible_and_unknown() {
    let mut binary = analyze(fixture("weak-version")).unwrap();
    binary
        .version_requirements
        .iter_mut()
        .find(|r| r.weak)
        .unwrap()
        .version = "GLIBC_PRIVATE".into();
    let result = compat::evaluate_glibc(&binary, "2.41".parse().unwrap());
    assert_eq!(result.status, Compatibility::Unknown);
    assert!(
        result.constraints[0]
            .reason
            .contains("weak version requirements")
    );
    assert_eq!(
        result.constraints[0].causing_symbols,
        ["pidfd_spawnp@GLIBC_PRIVATE"]
    );
}

#[test]
fn padded_interpreters_keep_the_same_path_and_still_validate_termination() {
    let padded = inspection("padded-interpreter");
    let plain = inspection("glibc-old");
    assert_eq!(padded.binary.interpreter, plain.binary.interpreter);
    assert_eq!(padded.compatibility[0].status, Compatibility::Compatible);

    let original = std::fs::read(fixture("padded-interpreter")).unwrap();
    let elf = ElfBytes::<AnyEndian>::minimal_parse(&original).unwrap();
    let interp = elf
        .segments()
        .unwrap()
        .iter()
        .find(|p| p.p_type == abi::PT_INTERP)
        .unwrap();
    let mut no_final_nul = original.clone();
    no_final_nul[(interp.p_offset + interp.p_filesz - 1) as usize] = b'x';
    assert!(analyze_bytes("unterminated", &no_final_nul).is_err());
    let mut empty_path = original.clone();
    empty_path[interp.p_offset as usize] = 0;
    assert!(analyze_bytes("empty interpreter", &empty_path).is_err());
}

#[test]
fn auxiliary_tags_can_repeat_without_hiding_other_dynamic_metadata() {
    let report = inspection("repeated-auxiliary");
    assert_eq!(report.compatibility[0].status, Compatibility::Compatible);
    assert_eq!(report.binary.needed_libraries, ["libc.so.6"]);
    assert_eq!(
        report
            .binary
            .glibc_requirement
            .as_ref()
            .unwrap()
            .minimum
            .to_string(),
        "2.17"
    );

    let data = std::fs::read(fixture("repeated-auxiliary")).unwrap();
    let elf = ElfBytes::<AnyEndian>::minimal_parse(&data).unwrap();
    let dynamic = elf.dynamic().unwrap().unwrap();
    assert_eq!(
        dynamic.iter().filter(|d| d.d_tag == DT_AUXILIARY).count(),
        2
    );
    // Singleton validation must survive the relaxation for repeatable tags.
    let slot = dynamic
        .iter()
        .position(|d| d.d_tag == DT_AUXILIARY)
        .unwrap();
    let strtab = dynamic.iter().find(|d| d.d_tag == abi::DT_STRTAB).unwrap();
    let segment = elf
        .segments()
        .unwrap()
        .iter()
        .find(|p| p.p_type == abi::PT_DYNAMIC)
        .unwrap();
    let offset = segment.p_offset as usize + slot * 16;
    let mut corrupt = data.clone();
    corrupt[offset..offset + 8].copy_from_slice(&abi::DT_STRTAB.to_le_bytes());
    corrupt[offset + 8..offset + 16].copy_from_slice(&(strtab.d_val() + 1).to_le_bytes());
    assert!(analyze_bytes("conflicting singleton", &corrupt).is_err());
}

#[test]
fn byte_aligned_vendor_notes_do_not_hide_gnu_isa_properties() {
    let data = std::fs::read(fixture("vendor-note")).unwrap();
    let elf = ElfBytes::<AnyEndian>::minimal_parse(&data).unwrap();
    let note = elf.section_header_by_name(".note.vendor").unwrap().unwrap();
    assert_eq!(note.sh_addralign, 1);
    let index = elf
        .section_headers()
        .unwrap()
        .iter()
        .position(|s| s.sh_name == note.sh_name)
        .unwrap();
    let header = elf.ehdr.e_shoff as usize + index * elf.ehdr.e_shentsize as usize;
    for alignment in [0u64, 1, 2] {
        let mut minimal_alignment = data.clone();
        minimal_alignment[header + 48..header + 56].copy_from_slice(&alignment.to_le_bytes());
        let binary = analyze_bytes("vendor note", &minimal_alignment).unwrap();
        assert_eq!(binary.cpu_requirement.x86_64_isa, Some(X86Isa::V3));
        assert_eq!(
            compat::evaluate(&binary, &distro("debian-12"), Some(X86Isa::V2)).status,
            Compatibility::Incompatible
        );
    }
    let mut truncated = data.clone();
    truncated[header + 32..header + 40].copy_from_slice(&(note.sh_size - 1).to_le_bytes());
    assert!(analyze_bytes("truncated vendor note", &truncated).is_err());
}

#[test]
fn regression_cases_have_consistent_cli_statuses() {
    for (name, extra, expected) in [
        ("abi-version-invalid", vec![], 1),
        ("abi-version-gnu", vec![], 3),
        ("weak-version", vec![], 3),
        ("weak-symbol-hard-version", vec![], 1),
        ("repeated-auxiliary", vec![], 0),
        ("padded-interpreter", vec![], 0),
        ("vendor-note", vec!["--cpu", "x86-64-v3"], 0),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_binport"))
            .arg(fixture(name))
            .args(["--target", "debian-12", "--fail-incompatible", "--json"])
            .args(extra)
            .env("PATH", "")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            json["compatibility"][0]["status"],
            match expected {
                0 => "compatible",
                1 => "incompatible",
                3 => "unknown",
                _ => unreachable!(),
            }
        );
    }
}
