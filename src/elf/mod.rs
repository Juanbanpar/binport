mod dynamic;
mod gnu_properties;
mod metadata;
mod symbol_versions;

use crate::{Error, model::*};
use ::elf::{ElfBytes, endian::AnyEndian};
use std::path::Path;

type Elf<'a> = ElfBytes<'a, AnyEndian>;
fn invalid(message: &str) -> Error {
    Error::Invalid(message.into())
}

pub(crate) fn analyze(file: &Path, data: &[u8]) -> Result<BinaryReport, Error> {
    if !data.starts_with(b"\x7fELF") {
        return Err(Error::NotElf);
    }
    let elf = Elf::minimal_parse(data)?;
    metadata::validate(&elf)?;
    let dynamic = dynamic::parse(&elf)?;
    let mut report = metadata::report(&elf, file, &dynamic)?;
    let (requirements, complete) = symbol_versions::parse(&elf, &dynamic)?;
    report.version_requirements = requirements;
    report.version_requirements_complete = complete;
    if !complete {
        report.warnings.push(AnalysisWarning::new("incomplete_symbol_versions", "Dynamic symbol/version sections are unavailable; the glibc floor and symbol causes may be incomplete."));
    }
    report.libc = symbol_versions::detect_libc(&report);
    report.glibc_requirement = symbol_versions::glibc_requirement(&report.version_requirements);
    report.cpu_requirement = gnu_properties::parse(&elf, report.architecture)?;
    if report.cpu_requirement.x86_64_isa.is_none() && report.architecture == Architecture::X86_64 {
        report.warnings.push(AnalysisWarning::new(
            "undeclared_cpu_isa",
            "No GNU ISA requirement was declared. This does NOT imply x86-64-v1 compatibility.",
        ));
    }
    if report.cpu_requirement.unknown_isa_bits != 0 {
        report.warnings.push(AnalysisWarning::new("unknown_cpu_isa_bits", "GNU properties contain ISA requirement bits not understood by this version of binport."));
    }
    if matches!(report.architecture, Architecture::Other(_)) {
        report.warnings.push(AnalysisWarning::new(
            "unsupported_architecture",
            "ELF metadata is reported, but this architecture is not deeply analyzed.",
        ));
    }
    Ok(report)
}
