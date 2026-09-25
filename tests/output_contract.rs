//! End-to-end, byte-for-byte CLI contracts. Only explicitly requested updates
//! may rewrite goldens; ordinary cargo test always compares committed outputs.
use std::{path::Path, process::Command};

fn golden(name: &str, actual: &[u8]) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var_os("BINPORT_UPDATE_GOLDENS").as_deref() == Some("1".as_ref()) {
        assert!(
            std::env::var_os("CI").is_none(),
            "do not update goldens in CI"
        );
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    assert_eq!(std::str::from_utf8(actual).unwrap(), expected, "{name}");
}

fn contract(name: &str, fixture: &str, args: &[&str], expected_code: i32) {
    for json in [false, true] {
        let mut reference = None;
        for explicit_inspect in [false, true] {
            for enforce in [false, true] {
                let mut cmd = Command::new(env!("CARGO_BIN_EXE_binport"));
                // Relative paths are part of the contract, avoiding checkout-path
                // normalization that might conceal changes to the emitted report.
                cmd.current_dir(env!("CARGO_MANIFEST_DIR"))
                    .env("PATH", "")
                    .env("NO_COLOR", "1");
                if explicit_inspect {
                    cmd.arg("inspect");
                }
                cmd.arg(format!("tests/fixtures/{fixture}")).args(args);
                if json {
                    cmd.arg("--json");
                }
                if enforce {
                    cmd.arg("--fail-incompatible");
                }
                let output = cmd.output().unwrap();
                let code = if enforce || expected_code == 2 {
                    expected_code
                } else {
                    0
                };
                assert_eq!(output.status.code(), Some(code), "{name}: {cmd:?}");
                let bytes = if expected_code == 2 {
                    assert!(output.stdout.is_empty(), "{name}: error on stdout");
                    output.stderr
                } else {
                    assert!(output.stderr.is_empty(), "{name}: success on stderr");
                    if json {
                        let inspection: binport::Inspection =
                            serde_json::from_slice(&output.stdout).unwrap();
                        assert_eq!(inspection.schema_version, 1);
                        assert!(!inspection.compatibility.is_empty());
                        let status = if inspection
                            .compatibility
                            .iter()
                            .any(|c| c.status == binport::Compatibility::Incompatible)
                        {
                            1
                        } else if inspection
                            .compatibility
                            .iter()
                            .any(|c| c.status == binport::Compatibility::Unknown)
                        {
                            3
                        } else {
                            0
                        };
                        assert_eq!(status, expected_code, "{name}: JSON/exit mismatch");
                    }
                    output.stdout
                };
                if let Some(previous) = &reference {
                    assert_eq!(&bytes, previous, "{name}: aliases/CI flag changed output");
                } else {
                    let extension = if json { "json" } else { "txt" };
                    golden(&format!("{name}.{extension}"), &bytes);
                    reference = Some(bytes);
                }
            }
        }
    }
}

macro_rules! case {
    ($name:ident, $fixture:literal, [$($arg:literal),*], $code:literal) => {
        #[test]
        fn $name() {
            contract(stringify!($name), $fixture, &[$($arg),*], $code);
        }
    };
}

case!(compatible, "glibc-new", ["--target", "debian-13"], 0);
case!(incompatible, "glibc-new", ["--target", "debian-12"], 1);
case!(
    incomplete_versions,
    "sectionless",
    ["--target", "debian-13"],
    3
);
case!(weak_missing, "weak-version", ["--target", "debian-12"], 3);
case!(weak_available, "weak-version", ["--target", "debian-13"], 0);
case!(
    weak_symbol_hard_version,
    "weak-symbol-hard-version",
    ["--target", "debian-12"],
    1
);
case!(
    cpu_incompatible,
    "x86-64-v3",
    ["--target", "debian-12", "--cpu", "x86-64-v2"],
    1
);
case!(glibc_ceiling, "glibc-new", ["--glibc-max", "2.31"], 1);
case!(
    failure_over_unknown,
    "weak-version",
    ["--target", "debian-12", "--glibc", "2.16"],
    1
);
case!(analysis_error, "non-elf", [], 2);
