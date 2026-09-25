use super::{
    Elf,
    dynamic::{Dynamic, at_vaddr},
    invalid,
};
use crate::{Error, model::*};
use ::elf::{
    abi,
    endian::EndianParse,
    gnu_symver::{VerNeed, VerNeedAux, VerNeedIterator, VersionIndexTable},
    parse::ParseAt,
    symbol::Symbol,
};
use std::collections::BTreeMap;

pub(super) fn parse(
    elf: &Elf<'_>,
    dynamic: &Dynamic<'_>,
) -> Result<(Vec<VersionRequirement>, bool), Error> {
    let headers = elf.section_headers();
    let needs = headers.and_then(|h| h.iter().find(|h| h.sh_type == abi::SHT_GNU_VERNEED));
    let versym = headers.and_then(|h| h.iter().find(|h| h.sh_type == abi::SHT_GNU_VERSYM));
    let dynsym = headers.and_then(|h| h.iter().find(|h| h.sh_type == abi::SHT_DYNSYM));
    let mut by_index = BTreeMap::new();
    if let Some(sh) = needs {
        let data = elf.section_data(&sh)?.0;
        let strings_header = headers
            .ok_or_else(|| invalid("missing section table"))?
            .get(sh.sh_link as usize)?;
        let strings = elf.section_data_as_strtab(&strings_header)?;
        validate_strings(elf, dynamic, &strings_header)?;
        validate_need_links(elf, data, sh.sh_info)?;
        // elf's GNU linked-list iterators silently stop on parse errors. Check the
        // declared counts and reject duplicate indices, rather than accepting a prefix.
        if sh.sh_info as usize > data.len() / 16 {
            return Err(invalid("invalid version requirement count"));
        }
        let mut iter = VerNeedIterator::new(
            elf.ehdr.endianness,
            elf.ehdr.class,
            sh.sh_info.into(),
            0,
            data,
        );
        let mut total_aux = 0usize;
        for _ in 0..sh.sh_info {
            let (need, mut aux) = iter
                .next()
                .ok_or_else(|| invalid("truncated version requirements"))?;
            let library = strings.get(need.vn_file as usize)?.to_owned();
            total_aux += usize::from(need.vn_cnt);
            if total_aux > data.len() / 16 {
                return Err(invalid("invalid version auxiliary count"));
            }
            for _ in 0..need.vn_cnt {
                let entry = aux
                    .next()
                    .ok_or_else(|| invalid("truncated version requirement auxiliaries"))?;
                let index = entry.vna_other & 0x7fff;
                let requirement = VersionRequirement {
                    library: library.clone(),
                    version: strings.get(entry.vna_name as usize)?.into(),
                    symbols: vec![],
                    weak: entry.vna_flags & abi::VER_FLG_WEAK != 0,
                };
                if index < 2 || by_index.insert(index, requirement).is_some() {
                    return Err(invalid("invalid or duplicate version requirement index"));
                }
            }
        }
    }
    let dynamic_needs = dynamic.tags.get(&abi::DT_VERNEEDNUM).copied().unwrap_or(0);
    if let Some(sh) = needs {
        if dynamic_needs != 0 && dynamic_needs != u64::from(sh.sh_info) {
            return Err(invalid("DT_VERNEEDNUM disagrees with section"));
        }
        if let Some(&address) = dynamic.tags.get(&abi::DT_VERNEED)
            && at_vaddr(elf, address, sh.sh_size)? != elf.section_data(&sh)?.0
        {
            return Err(invalid("DT_VERNEED disagrees with section"));
        }
    }
    let mut complete = dynamic_needs == 0 || needs.is_some();
    if let (Some(vs), Some(ds)) = (versym, dynsym) {
        if vs.sh_link as usize
            != headers
                .ok_or_else(|| invalid("missing sections"))?
                .iter()
                .position(|s| s.sh_type == abi::SHT_DYNSYM)
                .ok_or_else(|| invalid("missing dynsym"))?
        {
            return Err(invalid("version table does not link to dynsym"));
        }
        if vs.sh_entsize != 2 || ds.sh_entsize != Symbol::size_for(elf.ehdr.class) as u64 {
            return Err(invalid("incorrect symbol/version entry size"));
        }
        if let Some(&address) = dynamic.tags.get(&abi::DT_SYMTAB)
            && at_vaddr(elf, address, ds.sh_size)? != elf.section_data(&ds)?.0
        {
            return Err(invalid("DT_SYMTAB disagrees with section"));
        }
        let strings_header = headers
            .ok_or_else(|| invalid("missing sections"))?
            .get(ds.sh_link as usize)?;
        validate_strings(elf, dynamic, &strings_header)?;
        let indices = VersionIndexTable::new(
            elf.ehdr.endianness,
            elf.ehdr.class,
            elf.section_data(&vs)?.0,
        );
        let (symbols, strings) = elf
            .dynamic_symbol_table()?
            .ok_or_else(|| invalid("missing dynamic symbols"))?;
        if indices.len() != symbols.len() {
            return Err(invalid("dynsym and GNU version table lengths differ"));
        }
        if let Some(&address) = dynamic.tags.get(&abi::DT_VERSYM)
            && at_vaddr(elf, address, vs.sh_size)? != elf.section_data(&vs)?.0
        {
            return Err(invalid("DT_VERSYM disagrees with section"));
        }
        for i in 0..symbols.len() {
            let symbol = symbols.get(i)?;
            let name = strings.get(symbol.st_name as usize)?;
            let index = indices.get(i)?.index();
            if let Some(requirement) = by_index.get_mut(&index) {
                // Includes copy relocations: a defined dynsym can still refer to a need.
                if name.is_empty() {
                    return Err(invalid("versioned import has no symbol name"));
                }
                requirement.symbols.push(name.into());
            } else if symbol.is_undefined() && index > 1 {
                return Err(invalid("import references an unknown version index"));
            }
        }
    } else if needs.is_some() || dynamic.tags.contains_key(&abi::DT_VERSYM) {
        complete = false;
    }
    if dynsym.is_none() && dynamic.tags.contains_key(&abi::DT_SYMTAB) {
        complete = false;
    }
    let mut grouped: BTreeMap<(String, String, bool), Vec<String>> = BTreeMap::new();
    for requirement in by_index.into_values() {
        grouped
            .entry((requirement.library, requirement.version, requirement.weak))
            .or_default()
            .extend(requirement.symbols);
    }
    Ok((
        grouped
            .into_iter()
            .map(|((library, version, weak), mut symbols)| {
                symbols.sort();
                symbols.dedup();
                VersionRequirement {
                    library,
                    version,
                    symbols,
                    weak,
                }
            })
            .collect(),
        complete,
    ))
}

fn validate_strings(
    elf: &Elf<'_>,
    dynamic: &Dynamic<'_>,
    sh: &::elf::section::SectionHeader,
) -> Result<(), Error> {
    if let Some(&address) = dynamic.tags.get(&abi::DT_STRTAB)
        && at_vaddr(elf, address, sh.sh_size)? != elf.section_data(sh)?.0
    {
        return Err(invalid(
            "dynamic metadata uses a different string table from DT_STRTAB",
        ));
    }
    Ok(())
}

// Validate linked-list framing before using elf's infallible GNU iterators.
// The actual VerNeed/VerNeedAux records are still parsed by elf.
fn validate_need_links(elf: &Elf<'_>, data: &[u8], count: u32) -> Result<(), Error> {
    if count as usize > data.len() / 16 {
        return Err(invalid("invalid version requirement count"));
    }
    let endian = elf.ehdr.endianness;
    let mut offset = 0usize;
    let mut remaining_aux = data.len() / 16;
    for i in 0..count {
        let mut cursor = offset;
        let need = VerNeed::parse_at(endian, elf.ehdr.class, &mut cursor, data)?;
        let aux = endian.parse_u32_at(&mut (offset + 8), data)? as usize;
        let next = endian.parse_u32_at(&mut (offset + 12), data)? as usize;
        if need.vn_cnt == 0 || aux < 16 || need.vn_cnt as usize > remaining_aux {
            return Err(invalid("invalid GNU version auxiliary chain"));
        }
        remaining_aux -= need.vn_cnt as usize;
        let mut at = offset
            .checked_add(aux)
            .ok_or_else(|| invalid("version offset overflow"))?;
        for j in 0..need.vn_cnt {
            let mut cursor = at;
            VerNeedAux::parse_at(endian, elf.ehdr.class, &mut cursor, data)?;
            let jump = endian.parse_u32_at(&mut (at + 12), data)? as usize;
            if (j + 1 < need.vn_cnt && jump < 16) || (j + 1 == need.vn_cnt && jump != 0) {
                return Err(invalid("invalid GNU version auxiliary link"));
            }
            at = at
                .checked_add(jump)
                .ok_or_else(|| invalid("version offset overflow"))?;
        }
        if (i + 1 < count && next < 16) || (i + 1 == count && next != 0) {
            return Err(invalid("invalid GNU version requirement link"));
        }
        offset = offset
            .checked_add(next)
            .ok_or_else(|| invalid("version offset overflow"))?;
    }
    Ok(())
}

pub(super) fn glibc_requirement(requirements: &[VersionRequirement]) -> Option<GlibcRequirement> {
    let numeric: Vec<_> = requirements
        .iter()
        .filter(|r| glibc_object(&r.library) && !r.weak)
        .filter_map(|r| {
            r.version
                .strip_prefix("GLIBC_")?
                .parse::<LibcVersion>()
                .ok()
                .map(|v| (v, r))
        })
        .collect();
    let minimum = numeric.iter().map(|(v, _)| *v).max()?;
    let mut causing_symbols: Vec<_> = numeric
        .into_iter()
        .filter(|(v, _)| *v == minimum)
        .flat_map(|(_, r)| r.symbols.clone())
        .collect();
    causing_symbols.sort();
    causing_symbols.dedup();
    Some(GlibcRequirement {
        minimum,
        causing_symbols,
    })
}

pub(super) fn detect_libc(report: &BinaryReport) -> LibcInfo {
    if report.linking != Linking::Dynamic {
        return LibcInfo { family: LibcFamily::Unknown, evidence: vec!["Static or non-loadable artifact; embedded libc cannot be identified reliably from dynamic metadata.".into()] };
    }
    let mut glibc = Vec::new();
    let mut musl = Vec::new();
    let mut other = Vec::new();
    if let Some(path) = &report.interpreter {
        let name = path.rsplit('/').next().unwrap_or(path);
        if name.starts_with("ld-musl-") && name.ends_with(".so.1") {
            musl.push(format!("interpreter {path}"));
        } else if glibc_object(name) {
            glibc.push(format!("interpreter {path}"));
        } else {
            other.push(format!("unrecognized interpreter {path}"));
        }
    }
    for name in &report.needed_libraries {
        if name == "libc.so.6" {
            glibc.push(format!("DT_NEEDED {name}"));
        }
        if name.starts_with("libc.musl-") && name.ends_with(".so.1") {
            musl.push(format!("DT_NEEDED {name}"));
        }
        if matches!(name.as_str(), "libuClibc.so.0" | "libc.so.0") {
            other.push(format!("DT_NEEDED {name}"));
        }
    }
    if report
        .version_requirements
        .iter()
        .any(|r| glibc_object(&r.library) && r.version.starts_with("GLIBC_"))
    {
        glibc.push("GLIBC version requirements from glibc-provided objects".into());
    }
    let family = match (!glibc.is_empty(), !musl.is_empty(), !other.is_empty()) {
        (true, false, false) => LibcFamily::Glibc,
        (false, true, false) => LibcFamily::Musl,
        (false, false, true) => LibcFamily::Other,
        _ => LibcFamily::Unknown,
    };
    glibc.extend(musl);
    glibc.extend(other);
    LibcInfo {
        family,
        evidence: glibc,
    }
}
