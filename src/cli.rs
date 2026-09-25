use binport::{compat, model::*, report};
use clap::Parser;
use std::{ffi::OsString, io::Write, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    version,
    about = "Explain Linux ELF deployment compatibility without executing artifacts",
    after_help = "Also accepts: binport inspect <FILE> [OPTIONS]\nWithout --fail-incompatible, successful inspection exits 0. CI mode: 0 compatible, 1 incompatible, 2 error, 3 unknown.\nCompatibility covers declared ABI checks, not dependency availability or undeclared instructions."
)]
struct Cli {
    /// ELF artifact to inspect (never executed)
    file: PathBuf,
    /// Emit schema-versioned structured JSON
    #[arg(long)]
    json: bool,
    /// Target distribution id; repeat for multiple targets (default: all built-in releases)
    #[arg(long)]
    target: Vec<String>,
    /// Check an explicit maximum glibc requirement
    #[arg(long, visible_alias = "glibc-max")]
    glibc: Option<LibcVersion>,
    /// Explicit target CPU ISA (x86-64, x86-64-v2, x86-64-v3, x86-64-v4)
    #[arg(long)]
    cpu: Option<X86Isa>,
    /// Return CI exit codes for incompatibility or uncertainty
    #[arg(long)]
    fail_incompatible: bool,
}

pub fn run() -> ExitCode {
    let mut args: Vec<OsString> = std::env::args_os().collect();
    if args.get(1).is_some_and(|s| s == "inspect") {
        args.remove(1);
    }
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return ExitCode::from(code as u8);
        }
    };
    match inspect(&cli) {
        Ok(inspection) => {
            let output = if cli.json {
                report::json::render(&inspection).map(|s| format!("{s}\n"))
            } else {
                Ok(report::text::render(&inspection))
            };
            match output {
                Ok(text) => {
                    if let Err(error) = std::io::stdout().lock().write_all(text.as_bytes()) {
                        eprintln!("binport: {error}");
                        return ExitCode::from(2);
                    }
                }
                Err(error) => {
                    eprintln!("binport: {error}");
                    return ExitCode::from(2);
                }
            }
            let code = if !cli.fail_incompatible {
                0
            } else if inspection
                .compatibility
                .iter()
                .any(|c| c.status == Compatibility::Incompatible)
            {
                1
            } else if inspection
                .compatibility
                .iter()
                .any(|c| c.status == Compatibility::Unknown)
            {
                3
            } else {
                0
            };
            ExitCode::from(code)
        }
        Err(error) => {
            if cli.json {
                eprintln!(
                    "{}",
                    serde_json::json!({"schema_version": 1, "error": {"message": error}})
                );
            } else {
                eprintln!("binport: {error}");
            }
            ExitCode::from(2)
        }
    }
}

fn inspect(cli: &Cli) -> Result<Inspection, String> {
    let distros = compat::distro::built_in().map_err(|e| e.to_string())?;
    for id in &cli.target {
        if !distros.iter().any(|d| &d.id == id) {
            return Err(format!(
                "unknown target {id:?}; available: {}",
                distros
                    .iter()
                    .map(|d| d.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    if cli.cpu.is_some() && cli.glibc.is_some() && cli.target.is_empty() {
        return Err("--cpu requires --target when using a glibc-only policy".into());
    }
    let binary = binport::analyze(&cli.file).map_err(|e| e.to_string())?;
    if cli.cpu.is_some() && binary.architecture != Architecture::X86_64 {
        return Err("--cpu currently supports x86_64 artifacts only".into());
    }
    let mut compatibility = Vec::new();
    if cli.glibc.is_none() || !cli.target.is_empty() {
        for distro in &distros {
            if cli.target.is_empty() || cli.target.contains(&distro.id) {
                compatibility.push(compat::evaluate(&binary, distro, cli.cpu));
            }
        }
    }
    if let Some(maximum) = cli.glibc {
        compatibility.push(compat::evaluate_glibc(&binary, maximum));
    }
    Ok(Inspection {
        schema_version: 1,
        binary,
        compatibility,
    })
}
