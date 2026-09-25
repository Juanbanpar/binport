use super::{Elf, dynamic::Dynamic, invalid};
use crate::{Error, model::*};
use ::elf::{abi, endian::EndianParse, file::Class};
use std::collections::BTreeSet;
use std::path::Path;

// Validate ranges eagerly: elf's lazy iterators otherwise stop at malformed entries.
pub(super) fn validate(elf: &Elf<'_>) -> Result<(), Error> {
    if (elf.ehdr.e_phoff == 0 && elf.ehdr.e_phnum != 0)
        || (elf.ehdr.e_shoff == 0 && elf.ehdr.e_shnum != 0)
    {
        return Err(invalid("ELF table count has no table offset"));
    }
    if matches!(elf.ehdr.e_type, abi::ET_EXEC | abi::ET_DYN)
        && !elf
            .segments()
            .is_some_and(|h| h.iter().any(|p| p.p_type == abi::PT_LOAD))
    {
        return Err(invalid("loadable ELF artifact has no PT_LOAD segment"));
    }
    let expected = match elf.ehdr.class {
        Class::ELF32 => 52,
        Class::ELF64 => 64,
    };
    if elf.ehdr.e_ehsize != expected {
        return Err(invalid("incorrect ELF header size"));
    }
    if let Some(headers) = elf.segments() {
        for i in 0..headers.len() {
            let h = headers.get(i)?;
            elf.segment_data(&h)?;
            if h.p_type == abi::PT_LOAD && h.p_filesz > h.p_memsz {
                return Err(invalid("PT_LOAD file size exceeds memory size"));
            }
        }
    }
    if let Some(headers) = elf.section_headers() {
        let mut unique = BTreeSet::new();
        for i in 0..headers.len() {
            let h = headers.get(i)?;
            if matches!(
                h.sh_type,
                abi::SHT_DYNAMIC | abi::SHT_DYNSYM | abi::SHT_GNU_VERSYM | abi::SHT_GNU_VERNEED
            ) && !unique.insert(h.sh_type)
            {
                return Err(invalid("duplicate dynamic metadata section"));
            }
            if h.sh_type != abi::SHT_NOBITS && h.sh_type != abi::SHT_NULL {
                elf.section_data(&h)?;
            }
            if matches!(
                h.sh_type,
                abi::SHT_DYNAMIC | abi::SHT_DYNSYM | abi::SHT_GNU_VERSYM
            ) && (h.sh_entsize == 0 || h.sh_size % h.sh_entsize != 0)
            {
                return Err(invalid("truncated ELF table"));
            }
        }
    }
    Ok(())
}

pub(super) fn report(
    elf: &Elf<'_>,
    file: &Path,
    dynamic: &Dynamic<'_>,
) -> Result<BinaryReport, Error> {
    let mut interpreter = None;
    if let Some(headers) = elf.segments() {
        for h in headers.iter().filter(|h| h.p_type == abi::PT_INTERP) {
            if interpreter.is_some() {
                return Err(invalid("multiple PT_INTERP segments"));
            }
            let raw = elf.segment_data(&h)?;
            let name = raw
                .strip_suffix(&[0])
                .ok_or_else(|| invalid("PT_INTERP is not NUL terminated"))?;
            // Linux opens the C string, so trailing NUL padding is permitted.
            let name = name.split(|byte| *byte == 0).next().unwrap_or_default();
            if name.is_empty() {
                return Err(invalid("invalid PT_INTERP string"));
            }
            interpreter = Some(
                std::str::from_utf8(name)
                    .map_err(|_| invalid("PT_INTERP is not UTF-8"))?
                    .into(),
            );
        }
    }
    let binary_type = match elf.ehdr.e_type {
        abi::ET_EXEC => BinaryType::Executable,
        abi::ET_DYN if interpreter.is_some() || dynamic.pie => BinaryType::PieExecutable,
        abi::ET_DYN => BinaryType::SharedLibrary,
        abi::ET_REL => BinaryType::Relocatable,
        abi::ET_CORE => BinaryType::Core,
        _ => BinaryType::Other,
    };
    let linking = if matches!(
        binary_type,
        BinaryType::Relocatable | BinaryType::Core | BinaryType::Other
    ) {
        Linking::NotApplicable
    } else if interpreter.is_some()
        || !dynamic.needed.is_empty()
        || binary_type == BinaryType::SharedLibrary
    {
        Linking::Dynamic
    } else {
        Linking::Static
    };
    Ok(BinaryReport {
        file: file.into(),
        format: BinaryFormat::Elf,
        binary_type,
        architecture: match elf.ehdr.e_machine {
            abi::EM_X86_64 => Architecture::X86_64,
            abi::EM_AARCH64 => Architecture::Aarch64,
            n => Architecture::Other(n),
        },
        bits: match elf.ehdr.class {
            Class::ELF32 => 32,
            Class::ELF64 => 64,
        },
        endian: if elf.ehdr.endianness.is_little() {
            Endianness::Little
        } else {
            Endianness::Big
        },
        machine: elf.ehdr.e_machine,
        elf_type: elf.ehdr.e_type,
        os_abi: elf.ehdr.osabi,
        abi_version: elf.ehdr.abiversion,
        interpreter,
        linking,
        needed_libraries: dynamic.needed.clone(),
        soname: dynamic.soname.clone(),
        rpath: dynamic.rpath.clone(),
        runpath: dynamic.runpath.clone(),
        libc: LibcInfo {
            family: LibcFamily::Unknown,
            evidence: vec![],
        },
        version_requirements: vec![],
        version_requirements_complete: true,
        glibc_requirement: None,
        cpu_requirement: CpuRequirement::default(),
        warnings: vec![],
    })
}
