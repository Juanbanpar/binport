#![no_main]

use binport::{analyze_bytes, compat, model::*, report};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn check_verdict(result: &CompatibilityReport, binary: &BinaryReport) {
    if result.status == Compatibility::Compatible {
        assert!(binary.version_requirements_complete);
        assert!(result.constraints.iter().all(|c| {
            c.status != Compatibility::Incompatible
                && !(c.required && c.status == Compatibility::Unknown)
        }));
    }
    if !binary.version_requirements_complete {
        assert_ne!(result.status, Compatibility::Compatible);
    }
}

fuzz_target!(|data: &[u8]| {
    // Errors are expected. Panics, sanitizer findings and resource-limit failures
    // must reach libFuzzer so that it retains the reproducing bytes.
    let Ok(binary) = analyze_bytes("fuzz-input", data) else {
        return;
    };
    static RELEASES: OnceLock<Vec<compat::distro::DistroRelease>> = OnceLock::new();
    let releases = RELEASES.get_or_init(|| compat::distro::built_in().unwrap());
    let mut compatibility = Vec::new();
    for release in releases {
        let default = compat::evaluate(&binary, release, None);
        check_verdict(&default, &binary);
        compatibility.push(default);
        // Explicit CPU checking must not turn missing ISA metadata into a pass.
        let result = compat::evaluate(&binary, release, Some(X86Isa::Baseline));
        check_verdict(&result, &binary);
        if binary.architecture == Architecture::X86_64
            && binary.cpu_requirement.x86_64_isa.is_none()
        {
            assert_ne!(result.status, Compatibility::Compatible);
        }
        compatibility.push(result);
    }
    let ceiling: LibcVersion = "2.0".parse().unwrap();
    let policy = compat::evaluate_glibc(&binary, ceiling);
    check_verdict(&policy, &binary);
    if let Some(requirement) = &binary.glibc_requirement
        && requirement.minimum > ceiling
    {
        assert_eq!(policy.status, Compatibility::Incompatible);
        for symbol in &requirement.causing_symbols {
            // Every hard floor cause must be backed by a mandatory record.
            assert!(binary.version_requirements.iter().any(|r| {
                !r.weak
                    && r.version == format!("GLIBC_{}", requirement.minimum)
                    && r.symbols.contains(symbol)
            }));
        }
    }
    compatibility.push(policy);

    // Exercise consumers too: hostile metadata must be safe to render.
    let inspection = Inspection {
        schema_version: 1,
        binary,
        compatibility,
    };
    assert!(!report::text::render(&inspection).contains('\x1b'));
    report::json::render(&inspection).unwrap();

    // A known-invalid header must never be accepted, regardless of payload.
    // These fixed ELF header offsets are test mutations, not a second parser.
    let mut damaged = data.to_vec();
    let ehsize = if inspection.binary.bits == 64 { 52 } else { 40 };
    damaged[ehsize..ehsize + 2].fill(0);
    assert!(analyze_bytes("invalid-header", &damaged).is_err());

    // Removing version evidence cannot establish glibc compatibility while the
    // artifact still requests a dynamic glibc runtime. Arbitrary inputs can have
    // orphaned version sections, so absence alone need not set the incomplete flag.
    if !inspection.binary.version_requirements.is_empty() {
        let (offset, count) = if inspection.binary.bits == 64 {
            (40..48, 58..64)
        } else {
            (32..36, 46..52)
        };
        let mut sectionless = data.to_vec();
        sectionless[offset].fill(0);
        sectionless[count].fill(0);
        if let Ok(stripped) = analyze_bytes("removed-sections", &sectionless)
            && stripped.linking == Linking::Dynamic
            && stripped.libc.family == LibcFamily::Glibc
        {
            for release in releases {
                assert_ne!(
                    compat::evaluate(&stripped, release, None).status,
                    Compatibility::Compatible
                );
            }
        }
    }
});
