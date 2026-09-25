//! Static deployment compatibility analysis for Linux ELF artifacts.
pub mod compat;
mod elf;
pub mod model;
pub mod report;

use std::path::Path;

pub use model::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot read artifact: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid ELF: {0}")]
    Elf(#[from] ::elf::ParseError),
    #[error("invalid ELF: {0}")]
    Invalid(String),
    #[error("not an ELF file")]
    NotElf,
}

/// Reads an artifact as data only. Never executes it or resolves dependencies.
pub fn analyze(path: impl AsRef<Path>) -> Result<BinaryReport, Error> {
    let path = path.as_ref();
    analyze_bytes(path, &std::fs::read(path)?)
}

/// Analyze in-memory bytes; `file` is only a label for the report.
pub fn analyze_bytes(file: impl AsRef<Path>, bytes: &[u8]) -> Result<BinaryReport, Error> {
    elf::analyze(file.as_ref(), bytes)
}
