use crate::model::*;
use std::fmt::Write;

fn label(status: Compatibility) -> &'static str {
    match status {
        Compatibility::Compatible => "COMPATIBLE",
        Compatibility::Incompatible => "INCOMPATIBLE",
        Compatibility::Unknown => "UNKNOWN",
    }
}
// Escape untrusted control characters in filenames, symbols and loader strings.
fn safe(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

pub fn render(report: &Inspection) -> String {
    let b = &report.binary;
    let mut out = String::new();
    let kind = match b.binary_type {
        BinaryType::Executable => "executable (non-PIE)",
        BinaryType::PieExecutable => "PIE executable",
        BinaryType::SharedLibrary => "shared library",
        BinaryType::Relocatable => "relocatable",
        BinaryType::Core => "core dump",
        BinaryType::Other => "other",
    };
    let linking = match b.linking {
        Linking::Static => "static",
        Linking::Dynamic => "dynamic",
        Linking::NotApplicable => "not applicable",
    };
    writeln!(out, "{}\n\nBinary\n  Format: ELF{}\n  Architecture: {}\n  Endianness: {:?}\n  Type: {kind}\n  Linking: {linking}\n  e_machine: {}\n  e_type: {}", safe(&b.file.display().to_string()), b.bits, b.architecture, b.endian, b.machine, b.elf_type).ok();
    writeln!(
        out,
        "  OS ABI: {}\n  ABI version: {}",
        b.os_abi, b.abi_version
    )
    .ok();
    writeln!(
        out,
        "\nRuntime\n  Interpreter: {}\n  libc: {:?}",
        safe(b.interpreter.as_deref().unwrap_or("not declared")),
        b.libc.family
    )
    .ok();
    if let Some(g) = &b.glibc_requirement {
        writeln!(
            out,
            "  glibc >= {}\n\nglibc requirement\n  GLIBC_{}\n  Introduced by:",
            g.minimum, g.minimum
        )
        .ok();
        if g.causing_symbols.is_empty() {
            writeln!(
                out,
                "    version requirement record (no associated dynamic symbol)"
            )
            .ok();
        }
        for symbol in &g.causing_symbols {
            writeln!(out, "    {}@GLIBC_{}", safe(symbol), g.minimum).ok();
        }
    } else {
        writeln!(
            out,
            "  glibc requirement: {}",
            if b.linking == Linking::Static {
                "N/A (static)"
            } else {
                "not established"
            }
        )
        .ok();
    }
    writeln!(out, "\nDependencies").ok();
    if b.needed_libraries.is_empty() {
        writeln!(out, "  None declared").ok();
    }
    for lib in &b.needed_libraries {
        writeln!(out, "  {}", safe(lib)).ok();
    }
    if let Some(soname) = &b.soname {
        writeln!(out, "\nSONAME\n  {}", safe(soname)).ok();
    }
    for (title, paths) in [("RPATH", &b.rpath), ("RUNPATH", &b.runpath)] {
        if !paths.is_empty() {
            writeln!(out, "\n{title}").ok();
            for path in paths {
                writeln!(
                    out,
                    "  {}",
                    if path.is_empty() {
                        "(empty component: current directory)".into()
                    } else {
                        safe(path)
                    }
                )
                .ok();
            }
        }
    }
    if !b.version_requirements.is_empty() {
        writeln!(out, "\nImported symbol versions").ok();
        for r in &b.version_requirements {
            writeln!(
                out,
                "  {}: {}{}",
                safe(&r.library),
                safe(&r.version),
                if r.weak { " (weak version)" } else { "" }
            )
            .ok();
            for s in &r.symbols {
                writeln!(out, "    {}", safe(s)).ok();
            }
        }
    }
    writeln!(
        out,
        "\nCPU\n  ISA requirement: {}",
        b.cpu_requirement
            .x86_64_isa
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into())
    )
    .ok();
    writeln!(out, "\nCompatibility (declared ABI checks)").ok();
    for target in &report.compatibility {
        writeln!(out, "  {}: {}", safe(&target.name), label(target.status)).ok();
        for c in &target.constraints {
            writeln!(
                out,
                "    {}: {}\n      {}",
                c.constraint,
                label(c.status),
                safe(&c.reason)
            )
            .ok();
            for symbol in &c.causing_symbols {
                writeln!(out, "      {}", safe(symbol)).ok();
            }
        }
    }
    for warning in &b.warnings {
        writeln!(
            out,
            "\nWarning [{}]: {}",
            warning.code,
            safe(&warning.message)
        )
        .ok();
    }
    writeln!(out, "\nScope: declared ABI requirements only. Dependencies, non-glibc runtimes, kernel requirements and undeclared CPU instructions are not checked.").ok();
    out
}
