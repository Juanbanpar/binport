use super::distro::DistroRelease;
use crate::model::*;

fn check(
    name: &str,
    status: Compatibility,
    required: bool,
    reason: impl Into<String>,
) -> ConstraintResult {
    ConstraintResult {
        constraint: name.into(),
        status,
        required,
        reason: reason.into(),
        causing_symbols: vec![],
    }
}

pub fn overall_status(checks: &[ConstraintResult]) -> Compatibility {
    if checks
        .iter()
        .any(|c| c.status == Compatibility::Incompatible)
    {
        Compatibility::Incompatible
    } else if checks
        .iter()
        .any(|c| c.required && c.status == Compatibility::Unknown)
    {
        Compatibility::Unknown
    } else {
        Compatibility::Compatible
    }
}

fn glibc_check(binary: &BinaryReport, available: LibcVersion) -> ConstraintResult {
    use Compatibility::*;
    if let Some(required) = &binary.glibc_requirement
        && required.minimum > available
    {
        let mut result = check(
            "glibc",
            Incompatible,
            true,
            format!(
                "available glibc {available} < required {}; allowed maximum: GLIBC_{available}",
                required.minimum
            ),
        );
        result.causing_symbols = required
            .causing_symbols
            .iter()
            .map(|s| format!("{s}@GLIBC_{}", required.minimum))
            .collect();
        return result;
    }
    if !binary.version_requirements_complete {
        return check(
            "glibc",
            Unknown,
            true,
            "Symbol-version metadata is incomplete; cannot establish the glibc floor.",
        );
    }
    let nonnumeric: Vec<_> = binary
        .version_requirements
        .iter()
        .filter(|r| {
            !r.weak
                && glibc_object(&r.library)
                && r.version.starts_with("GLIBC_")
                && r.version[6..].parse::<LibcVersion>().is_err()
        })
        .map(|r| format!("{} from {}", r.version, r.library))
        .collect();
    if !nonnumeric.is_empty() {
        return check(
            "glibc",
            Unknown,
            true,
            format!(
                "Non-numeric glibc ABI requirements cannot be decided from release versions: {}",
                nonnumeric.join(", ")
            ),
        );
    }
    if binary.linking == Linking::Static {
        return check(
            "glibc",
            Compatible,
            true,
            "Not applicable: no dynamic libc requirement (embedded libc is unknown).",
        );
    }
    let unavailable_weak: Vec<_> = binary
        .version_requirements
        .iter()
        .filter(|r| {
            r.weak
                && glibc_object(&r.library)
                && r.version
                    .strip_prefix("GLIBC_")
                    .is_some_and(|v| v.parse::<LibcVersion>().map_or(true, |v| v > available))
        })
        .collect();
    if !unavailable_weak.is_empty() {
        let mut result = check(
            "glibc",
            Unknown,
            true,
            format!(
                "Mandatory glibc floor does not exceed {available}, but weak version requirements are not established on this target: {}. Weak-symbol binding and fallback behavior are not evaluated.",
                unavailable_weak
                    .iter()
                    .map(|r| format!("{} from {}", r.version, r.library))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
        result.causing_symbols = unavailable_weak
            .iter()
            .flat_map(|r| r.symbols.iter().map(|s| format!("{s}@{}", r.version)))
            .collect();
        result.causing_symbols.sort();
        result.causing_symbols.dedup();
        return result;
    }
    match binary.libc.family {
        LibcFamily::Musl | LibcFamily::None => check(
            "glibc",
            Compatible,
            true,
            "Not applicable: no glibc runtime dependency identified.",
        ),
        LibcFamily::Glibc => match &binary.glibc_requirement {
            Some(required) => check(
                "glibc",
                Compatible,
                true,
                format!(
                    "available glibc {available} >= required {}",
                    required.minimum
                ),
            ),
            None => check(
                "glibc",
                Unknown,
                true,
                "glibc runtime requested, but no numeric GLIBC version floor is declared.",
            ),
        },
        _ => check(
            "glibc",
            Unknown,
            true,
            "libc family or glibc ABI floor cannot be established.",
        ),
    }
}

/// Check only the explicit glibc ceiling. This is an ABI policy, not a deployment verdict.
pub fn evaluate_glibc(binary: &BinaryReport, maximum: LibcVersion) -> CompatibilityReport {
    let constraints = vec![glibc_check(binary, maximum)];
    CompatibilityReport {
        target: format!("glibc-{maximum}"),
        name: format!("glibc maximum {maximum}"),
        status: overall_status(&constraints),
        constraints,
    }
}

/// Check the matching architecture edition of a distribution, without host inspection.
/// `cpu` is an optional explicit target-machine ISA; a distro does not specify a CPU.
pub fn evaluate(
    binary: &BinaryReport,
    target: &DistroRelease,
    cpu: Option<X86Isa>,
) -> CompatibilityReport {
    use Compatibility::*;
    let mut constraints = Vec::new();
    let supported = matches!(
        binary.architecture,
        Architecture::X86_64 | Architecture::Aarch64
    );
    constraints.push(
        if !supported || binary.bits != 64 || binary.endian != Endianness::Little {
            check(
                "architecture",
                Unknown,
                true,
                format!(
                    "{} ELF{} {:?} ABI is outside the supported 64-bit little-endian profiles",
                    binary.architecture, binary.bits, binary.endian
                ),
            )
        } else if target.architectures.contains(&binary.architecture) {
            check(
                "architecture",
                Compatible,
                true,
                format!("{} edition is supported", binary.architecture),
            )
        } else {
            check(
                "architecture",
                Incompatible,
                true,
                format!(
                    "{} is not a supported architecture for {}",
                    binary.architecture, target.id
                ),
            )
        },
    );
    if !matches!(
        binary.binary_type,
        BinaryType::Executable | BinaryType::PieExecutable | BinaryType::SharedLibrary
    ) {
        constraints.push(check(
            "artifact_type",
            Unknown,
            true,
            "This artifact is not an executable or shared library.",
        ));
    }
    if !matches!(binary.os_abi, 0 | 3) {
        constraints.push(check(
            "os_abi",
            Unknown,
            true,
            format!(
                "ELF OS ABI {} is not the supported System V/Linux profile",
                binary.os_abi
            ),
        ));
    }
    if binary.abi_version != 0 {
        // glibc's System V DSO profile accepts only ABI version zero. GNU ABI
        // extensions are loader/version-specific, so do not guess their support.
        let invalid_sysv_dso = binary.os_abi == 0
            && binary.binary_type == BinaryType::SharedLibrary
            && target.libc == LibcFamily::Glibc;
        constraints.push(check("abi_version", if invalid_sysv_dso { Incompatible } else { Unknown }, true,
            if invalid_sysv_dso {
                format!("ELF ABI version {} is invalid for a System V shared library: the target glibc loader requires version 0.", binary.abi_version)
            } else {
                format!("ELF OS ABI {} version {} is outside the supported version-0 profile; loader compatibility is unknown.", binary.os_abi, binary.abi_version)
            }
        ));
    }
    constraints.push(if binary.linking == Linking::Static {
        check("dynamic_loader", Compatible, true, "Not applicable: statically linked.")
    } else if matches!(binary.libc.family, LibcFamily::Glibc | LibcFamily::Musl) && binary.libc.family != target.libc {
        check("dynamic_loader", Incompatible, true, format!("artifact requests {:?}, target baseline provides {:?}; interpreter {}", binary.libc.family, target.libc, binary.interpreter.as_deref().unwrap_or("not declared")))
    } else if binary.libc.family != target.libc {
        check("dynamic_loader", Unknown, true, "Runtime family cannot be matched to the target baseline.")
    } else if let Some(interpreter) = &binary.interpreter {
        let expected = match binary.architecture { Architecture::X86_64 => &target.x86_64_interpreter, Architecture::Aarch64 => &target.aarch64_interpreter, _ => "" };
        if interpreter == expected { check("dynamic_loader", Compatible, true, format!("target baseline loader: {interpreter}")) }
        else { check("dynamic_loader", Unknown, true, format!("requested interpreter {interpreter}; target baseline uses {expected}; custom path availability is unknown")) }
    } else if binary.binary_type == BinaryType::SharedLibrary {
        check("dynamic_loader", Compatible, true, "Shared library uses the consuming process's matching runtime family.")
    } else { check("dynamic_loader", Unknown, true, "Dynamic executable has no declared interpreter.") });
    constraints.push(glibc_check(binary, target.glibc));
    constraints.push(if binary.cpu_requirement.unknown_isa_bits != 0 {
        check("cpu_isa", Unknown, true, format!("Unrecognized GNU ISA requirement bits: {:#x}", binary.cpu_requirement.unknown_isa_bits))
    } else if binary.architecture != Architecture::X86_64 {
        check("cpu_isa", Unknown, false, "ISA requirement analysis is not implemented for this architecture.")
    } else if let Some(required) = binary.cpu_requirement.x86_64_isa {
        if let Some(available) = cpu {
            check("cpu_isa", if required <= available { Compatible } else { Incompatible }, true, format!("declared requirement {required}; target CPU {available}"))
        } else if required == X86Isa::Baseline {
            check("cpu_isa", Compatible, true, "Declared baseline x86-64 requirement.")
        } else { check("cpu_isa", Unknown, true, format!("Declared requirement {required}; distribution version does not identify the target CPU. Supply --cpu.")) }
    } else { check("cpu_isa", Unknown, cpu.is_some(), "No GNU ISA requirement was declared. This does NOT imply x86-64-v1 compatibility.") });
    CompatibilityReport {
        target: target.id.clone(),
        name: format!("{} {}", target.name, target.version),
        status: overall_status(&constraints),
        constraints,
    }
}
