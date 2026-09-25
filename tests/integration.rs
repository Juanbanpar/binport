use binport::{analyze, analyze_bytes, compat, model::*, report};
use std::{
    path::PathBuf,
    process::{Command, Output},
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}
fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).unwrap()
}
fn inspect(name: &str) -> BinaryReport {
    analyze(fixture(name)).unwrap()
}
fn target(id: &str) -> compat::distro::DistroRelease {
    compat::distro::built_in()
        .unwrap()
        .into_iter()
        .find(|d| d.id == id)
        .unwrap()
}
fn cli(name: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_binport"))
        .arg(fixture(name))
        .args(args)
        .env("PATH", "")
        .output()
        .unwrap()
}

#[test]
fn elf_kinds_and_linking() {
    for (name, kind, linking) in [
        ("pie", BinaryType::PieExecutable, Linking::Dynamic),
        ("non-pie", BinaryType::Executable, Linking::Dynamic),
        (
            "shared-library",
            BinaryType::SharedLibrary,
            Linking::Dynamic,
        ),
        ("static-glibc", BinaryType::Executable, Linking::Static),
        ("static-pie", BinaryType::PieExecutable, Linking::Static),
        (
            "relocatable",
            BinaryType::Relocatable,
            Linking::NotApplicable,
        ),
    ] {
        let report = inspect(name);
        assert_eq!(report.binary_type, kind, "{name}");
        assert_eq!(report.linking, linking, "{name}");
    }
}

#[test]
fn metadata_and_interpreter() {
    let report = inspect("pie");
    assert_eq!(report.bits, 64);
    assert_eq!(report.machine, 62);
    assert_eq!(report.elf_type, 3);
    assert_eq!(report.endian, Endianness::Little);
    assert_eq!(
        report.interpreter.as_deref(),
        Some("/lib64/ld-linux-x86-64.so.2")
    );
    assert_eq!(
        inspect("shared-library").soname.as_deref(),
        Some("libtiny.so.1")
    );
}

#[test]
fn elf32_and_big_endian_are_parsed_without_assuming_host_abi() {
    let report = inspect("elf32");
    assert_eq!(report.bits, 32);
    assert_eq!(report.architecture, Architecture::Other(3));
    assert_eq!(
        compat::evaluate(&report, &target("debian-12"), None).status,
        Compatibility::Unknown
    );
    let report = inspect("aarch64-big-endian");
    assert_eq!(report.architecture, Architecture::Aarch64);
    assert_eq!(report.endian, Endianness::Big);
}

#[test]
fn aarch64_has_full_symbol_version_analysis() {
    let report = inspect("aarch64-glibc-new");
    assert_eq!(report.architecture, Architecture::Aarch64);
    assert_eq!(
        report.interpreter.as_deref(),
        Some("/lib/ld-linux-aarch64.so.1")
    );
    assert_eq!(
        report
            .glibc_requirement
            .as_ref()
            .unwrap()
            .minimum
            .to_string(),
        "2.39"
    );
    assert_eq!(
        compat::evaluate(&report, &target("debian-12"), None).status,
        Compatibility::Incompatible
    );
    assert_eq!(
        compat::evaluate(&report, &target("debian-13"), None).status,
        Compatibility::Compatible
    );
}

#[test]
fn dynamic_paths_preserve_tokens_and_empty_components() {
    let report = inspect("runpath");
    assert_eq!(report.needed_libraries, ["libc.so.6"]);
    assert_eq!(report.runpath, ["$ORIGIN/lib", "", "/opt/lib"]);
    assert!(report.rpath.is_empty());
    let report = inspect("rpath");
    assert_eq!(report.rpath, ["$ORIGIN/old"]);
    assert!(report.runpath.is_empty());
}

#[test]
fn exact_provider_version_symbol_associations() {
    let report = inspect("glibc-new");
    assert!(report.version_requirements_complete);
    let old = report
        .version_requirements
        .iter()
        .find(|r| r.version == "GLIBC_2.2.5")
        .unwrap();
    assert_eq!(old.library, "libc.so.6");
    assert_eq!(old.symbols, ["free", "malloc"]);
    let new = report
        .version_requirements
        .iter()
        .find(|r| r.version == "GLIBC_2.39")
        .unwrap();
    assert_eq!(new.symbols, ["pidfd_spawn", "pidfd_spawnp"]);
    let glibc = report.glibc_requirement.unwrap();
    assert_eq!(glibc.minimum.to_string(), "2.39");
    assert_eq!(glibc.causing_symbols, ["pidfd_spawn", "pidfd_spawnp"]);
    assert_eq!(
        inspect("glibc-old")
            .glibc_requirement
            .unwrap()
            .minimum
            .to_string(),
        "2.17"
    );
}

#[test]
fn numeric_version_ordering() {
    for (lower, higher) in [
        ("2.9", "2.10"),
        ("2.17", "2.31"),
        ("2.39", "2.40"),
        ("2.2", "2.2.5"),
    ] {
        assert!(lower.parse::<LibcVersion>().unwrap() < higher.parse().unwrap());
    }
    assert_eq!(
        "2.39".parse::<LibcVersion>().unwrap(),
        "2.39.0".parse().unwrap()
    );
    for bad in [
        "2",
        "2.",
        ".31",
        "2.3.4.5",
        "GLIBC_2.31",
        "2.-1",
        "2.31junk",
        "2.4294967296",
        " 2.31",
    ] {
        assert!(bad.parse::<LibcVersion>().is_err(), "{bad}");
    }
}

#[test]
fn namespaces_and_decoys_do_not_raise_glibc_floor() {
    let report = inspect("namespaces");
    for version in [
        "GLIBCXX_3.4.30",
        "CXXABI_1.3",
        "GCC_3.0",
        "OPENSSL_3.0.0",
        "GLIBC_9.99",
    ] {
        assert!(
            report
                .version_requirements
                .iter()
                .any(|r| r.version == version)
        );
    }
    assert_eq!(
        report.glibc_requirement.unwrap().minimum.to_string(),
        "2.17"
    );
    assert!(
        !report
            .version_requirements
            .iter()
            .any(|r| r.version == "GLIBC_99.99")
    );
}

#[test]
fn hidden_version_bit_is_masked() {
    assert_eq!(
        inspect("hidden-version-index").version_requirements,
        inspect("glibc-new").version_requirements
    );
}

#[test]
fn elf32_dynamic_versions_and_export_only_versions() {
    let binary = inspect("i386-glibc-new");
    assert_eq!(binary.bits, 32);
    assert_eq!(binary.linking, Linking::Dynamic);
    assert_eq!(
        binary.glibc_requirement.unwrap().minimum.to_string(),
        "2.39"
    );
    let provider = inspect("versioned-provider");
    assert!(provider.version_requirements.is_empty());
    assert!(provider.glibc_requirement.is_none());
}

#[test]
fn copy_relocated_imports_keep_their_version_requirements() {
    let binary = inspect("copy-relocation");
    assert_eq!(
        binary
            .glibc_requirement
            .as_ref()
            .unwrap()
            .minimum
            .to_string(),
        "2.39"
    );
    assert_eq!(
        binary.glibc_requirement.unwrap().causing_symbols,
        ["imported_data"]
    );
    let data = bytes("copy-relocation");
    let elf = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data).unwrap();
    let (symbols, strings) = elf.dynamic_symbol_table().unwrap().unwrap();
    let imported = symbols
        .iter()
        .find(|s| strings.get(s.st_name as usize).unwrap() == "imported_data")
        .unwrap();
    assert!(
        !imported.is_undefined(),
        "fixture must exercise a defined copy-relocated symbol"
    );
}

#[test]
fn unrelated_nonnumeric_glibc_namespace_is_preserved_without_affecting_floor() {
    let mut binary = inspect("glibc-old");
    binary.version_requirements.push(VersionRequirement {
        library: "libunrelated.so.1".into(),
        version: "GLIBC_CUSTOM".into(),
        symbols: vec!["custom".into()],
        weak: false,
    });
    assert_eq!(
        compat::evaluate_glibc(&binary, "2.31".parse().unwrap()).status,
        Compatibility::Compatible
    );
}

#[test]
fn corrupt_version_chains_and_interpreter_return_errors() {
    let original = bytes("glibc-new");
    let elf = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&original).unwrap();
    let need = elf
        .section_headers()
        .unwrap()
        .iter()
        .find(|s| s.sh_type == elf::abi::SHT_GNU_VERNEED)
        .unwrap();
    for (relative, replacement) in [
        (2, vec![255, 255]),
        (8, vec![0, 0, 0, 0]),
        (12, vec![16, 0, 0, 0]),
    ] {
        let mut damaged = original.clone();
        let at = need.sh_offset as usize + relative;
        damaged[at..at + replacement.len()].copy_from_slice(&replacement);
        assert!(analyze_bytes("bad-chain", &damaged).is_err());
    }
    let interp = elf
        .segments()
        .unwrap()
        .iter()
        .find(|s| s.p_type == elf::abi::PT_INTERP)
        .unwrap();
    let mut damaged = original.clone();
    damaged[(interp.p_offset + interp.p_filesz - 1) as usize] = b'x';
    assert!(analyze_bytes("bad-interp", &damaged).is_err());
}

#[test]
fn truncated_property_payload_is_not_silently_ignored() {
    let original = bytes("x86-64-v3");
    let elf = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&original).unwrap();
    let note = elf
        .section_header_by_name(".note.gnu.property")
        .unwrap()
        .unwrap();
    let mut damaged = original.clone();
    let size_at = note.sh_offset as usize + 20;
    damaged[size_at..size_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(analyze_bytes("bad-note", &damaged).is_err());
}

#[test]
fn missing_version_sections_with_dynamic_tags_are_not_a_pass() {
    let original = bytes("glibc-new");
    let elf = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&original).unwrap();
    let index = elf
        .section_headers()
        .unwrap()
        .iter()
        .position(|s| s.sh_type == elf::abi::SHT_GNU_VERNEED)
        .unwrap();
    let mut damaged = original.clone();
    let at = elf.ehdr.e_shoff as usize + index * elf.ehdr.e_shentsize as usize + 4;
    damaged[at..at + 4].copy_from_slice(&elf::abi::SHT_PROGBITS.to_le_bytes());
    // Symbols still reference the removed needs, so reject the dangling indices.
    assert!(analyze_bytes("missing-needs", &damaged).is_err());
}

#[test]
fn musl_and_static_libc_classification() {
    assert_eq!(inspect("musl-dynamic").libc.family, LibcFamily::Musl);
    for name in ["musl-static", "static-glibc", "static-pie"] {
        let report = inspect(name);
        assert_eq!(report.linking, Linking::Static);
        assert_eq!(report.libc.family, LibcFamily::Unknown);
        assert!(report.glibc_requirement.is_none());
    }
    let mut report = inspect("shared-library");
    report.libc.family = LibcFamily::Unknown;
    report.glibc_requirement = None;
    assert_eq!(
        compat::evaluate_glibc(&report, "2.31".parse().unwrap()).status,
        Compatibility::Unknown
    );
}

#[test]
fn cpu_properties_are_requirements_only_when_declared_needed() {
    for (name, isa) in [
        ("x86-64-v2", X86Isa::V2),
        ("x86-64-v3", X86Isa::V3),
        ("x86-64-v4", X86Isa::V4),
    ] {
        assert_eq!(inspect(name).cpu_requirement.x86_64_isa, Some(isa));
    }
    assert!(
        inspect("isa-used-only")
            .cpu_requirement
            .x86_64_isa
            .is_none()
    );
    assert_eq!(
        inspect("isa-unknown-bits").cpu_requirement.unknown_isa_bits,
        16
    );
    let report = inspect("glibc-new");
    assert!(report.cpu_requirement.x86_64_isa.is_none());
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.message.contains("does NOT imply x86-64-v1 compatibility"))
    );
}

#[test]
fn declared_cpu_checks_do_not_treat_distro_baseline_as_cpu_ceiling() {
    let report = inspect("x86-64-v3");
    let distro = target("debian-12");
    assert_eq!(
        compat::evaluate(&report, &distro, None).status,
        Compatibility::Unknown
    );
    assert_eq!(
        compat::evaluate(&report, &distro, Some(X86Isa::V2)).status,
        Compatibility::Incompatible
    );
    assert_eq!(
        compat::evaluate(&report, &distro, Some(X86Isa::V3)).status,
        Compatibility::Compatible
    );
    assert_eq!(
        compat::evaluate(&inspect("glibc-old"), &distro, Some(X86Isa::V3)).status,
        Compatibility::Unknown
    );
}

#[test]
fn distro_abi_results_and_concrete_causes() {
    let binary = inspect("glibc-new");
    for id in ["ubuntu-20.04", "ubuntu-22.04", "debian-12", "rhel-9"] {
        let report = compat::evaluate(&binary, &target(id), None);
        assert_eq!(report.status, Compatibility::Incompatible, "{id}");
        assert!(report.constraints.iter().any(|c| {
            c.causing_symbols
                .contains(&"pidfd_spawnp@GLIBC_2.39".to_string())
        }));
    }
    for id in ["ubuntu-24.04", "debian-13"] {
        let report = compat::evaluate(&binary, &target(id), None);
        assert_eq!(report.status, Compatibility::Compatible);
        assert!(report.constraints.iter().any(|c| c.constraint == "cpu_isa"
            && c.status == Compatibility::Unknown
            && !c.required));
    }
}

#[test]
fn loader_family_and_custom_loader_checks() {
    let distro = target("debian-13");
    let report = compat::evaluate(&inspect("musl-dynamic"), &distro, None);
    assert_eq!(report.status, Compatibility::Incompatible);
    assert!(
        report
            .constraints
            .iter()
            .any(|c| c.constraint == "dynamic_loader" && c.reason.contains("Musl"))
    );
    let mut report = inspect("glibc-new");
    report.interpreter = Some("/custom/ld-linux-x86-64.so.2".into());
    assert_eq!(
        compat::evaluate(&report, &distro, None).status,
        Compatibility::Unknown
    );
}

#[test]
fn unsupported_target_architecture_and_non_loadable_artifacts() {
    let mut distro = target("debian-13");
    distro.architectures = vec![Architecture::Aarch64];
    assert_eq!(
        compat::evaluate(&inspect("glibc-new"), &distro, None).status,
        Compatibility::Incompatible
    );
    assert_eq!(
        compat::evaluate(&inspect("relocatable"), &distro, None).status,
        Compatibility::Incompatible
    );
    assert_eq!(
        compat::evaluate(&inspect("relocatable"), &target("debian-13"), None).status,
        Compatibility::Unknown
    );
}

#[test]
fn missing_section_metadata_is_unknown_not_a_false_pass() {
    let report = inspect("sectionless");
    assert_eq!(report.needed_libraries, ["libc.so.6"]);
    assert!(!report.version_requirements_complete);
    assert_eq!(
        compat::evaluate(&report, &target("debian-13"), None).status,
        Compatibility::Unknown
    );
}

#[test]
fn nonnumeric_glibc_requirements_are_not_ignored() {
    let mut binary = inspect("glibc-old");
    binary.version_requirements.push(VersionRequirement {
        library: "libc.so.6".into(),
        version: "GLIBC_PRIVATE".into(),
        symbols: vec!["private_api".into()],
        weak: false,
    });
    assert_eq!(
        compat::evaluate_glibc(&binary, "2.41".parse().unwrap()).status,
        Compatibility::Unknown
    );
}

#[test]
fn malformed_files_return_errors() {
    for name in [
        "non-elf",
        "malformed-elf",
        "truncated-elf",
        "bad-version-index",
        "bad-verneed",
    ] {
        assert!(analyze(fixture(name)).is_err(), "{name}");
    }
    assert!(analyze(fixture("does-not-exist")).is_err());
    assert!(analyze_bytes("empty", &[]).is_err());
}

#[test]
fn every_truncated_prefix_fails_without_panicking() {
    let data = bytes("glibc-new");
    for end in 0..data.len() {
        assert!(
            analyze_bytes("truncated", &data[..end]).is_err(),
            "prefix length {end}"
        );
    }
}

#[test]
fn deterministic_mutation_smoke_test_never_panics() {
    for name in ["glibc-new", "x86-64-v3", "aarch64-glibc-new", "elf32"] {
        let data = bytes(name);
        let mut state = 0x1234_5678u64;
        for _ in 0..1500 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let mut mutated = data.clone();
            let index = (state >> 32) as usize % mutated.len();
            mutated[index] ^= (state as u8).max(1);
            let _ = analyze_bytes("mutated", &mutated);
        }
    }
}

#[test]
fn bundled_database_is_unique_and_has_provenance() {
    let releases = compat::distro::built_in().unwrap();
    let ids: std::collections::BTreeSet<_> = releases.iter().map(|d| &d.id).collect();
    assert_eq!(ids.len(), releases.len());
    for d in releases {
        assert!(d.source.starts_with("https://"));
        assert_eq!(d.verified, "2026-09-20");
    }
}

#[test]
fn json_and_text_share_the_same_causes_and_unknowns() {
    let binary = inspect("glibc-new");
    let compatibility = vec![compat::evaluate(&binary, &target("debian-12"), None)];
    let inspection = Inspection {
        schema_version: 1,
        binary,
        compatibility,
    };
    let json: serde_json::Value =
        serde_json::from_str(&report::json::render(&inspection).unwrap()).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["binary"]["glibc_requirement"]["minimum"], "2.39");
    assert_eq!(json["compatibility"][0]["status"], "incompatible");
    let text = report::text::render(&inspection);
    assert!(text.contains("pidfd_spawnp@GLIBC_2.39"));
    assert!(text.contains("does NOT imply x86-64-v1 compatibility"));
    assert!(text.contains("available glibc 2.36 < required 2.39"));
}

#[test]
fn text_escapes_terminal_controls() {
    let mut binary = inspect("glibc-new");
    binary.needed_libraries.push("evil\x1b[31m\nspoof".into());
    let text = report::text::render(&Inspection {
        schema_version: 1,
        binary,
        compatibility: vec![],
    });
    assert!(!text.contains('\x1b'));
    assert!(text.contains("evil\\u{1b}[31m\\nspoof"));
}

#[test]
fn default_and_inspect_commands_are_identical() {
    let default = cli("glibc-new", &["--json", "--target", "debian-12"]);
    let explicit = Command::new(env!("CARGO_BIN_EXE_binport"))
        .arg("inspect")
        .arg(fixture("glibc-new"))
        .args(["--json", "--target", "debian-12"])
        .output()
        .unwrap();
    assert_eq!(default.status.code(), Some(0));
    assert_eq!(default.stdout, explicit.stdout);
}

#[test]
fn cli_exit_codes_cover_all_four_outcomes() {
    for (name, args, code) in [
        (
            "glibc-new",
            vec!["--target", "debian-13", "--fail-incompatible"],
            0,
        ),
        (
            "glibc-new",
            vec!["--target", "debian-12", "--fail-incompatible"],
            1,
        ),
        ("malformed-elf", vec!["--fail-incompatible"], 2),
        (
            "sectionless",
            vec!["--target", "debian-13", "--fail-incompatible"],
            3,
        ),
        (
            "glibc-new",
            vec!["--glibc-max", "2.31", "--fail-incompatible"],
            1,
        ),
        (
            "glibc-new",
            vec!["--glibc", "2.39", "--fail-incompatible"],
            0,
        ),
        ("glibc-new", vec!["--target", "missing"], 2),
        ("glibc-new", vec!["--glibc", "2.nope"], 2),
        (
            "glibc-new",
            vec![
                "--target",
                "debian-13",
                "--target",
                "debian-12",
                "--fail-incompatible",
            ],
            1,
        ),
    ] {
        let output = cli(name, &args);
        assert_eq!(
            output.status.code(),
            Some(code),
            "{name} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn cli_json_errors_and_no_external_commands() {
    let output = cli("malformed-elf", &["--json"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(error["error"]["message"].as_str().unwrap().contains("ELF"));
    let output = cli("glibc-new", &["--json", "--glibc", "2.31"]);
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["compatibility"].as_array().unwrap().len(), 1);
}
