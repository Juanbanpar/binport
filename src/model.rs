use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf, str::FromStr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryReport {
    pub file: PathBuf,
    pub format: BinaryFormat,
    pub binary_type: BinaryType,
    pub architecture: Architecture,
    pub bits: u8,
    pub endian: Endianness,
    pub machine: u16,
    pub elf_type: u16,
    pub os_abi: u8,
    pub abi_version: u8,
    pub interpreter: Option<String>,
    pub linking: Linking,
    pub needed_libraries: Vec<String>,
    pub soname: Option<String>,
    pub rpath: Vec<String>,
    pub runpath: Vec<String>,
    pub libc: LibcInfo,
    pub version_requirements: Vec<VersionRequirement>,
    pub version_requirements_complete: bool,
    pub glibc_requirement: Option<GlibcRequirement>,
    pub cpu_requirement: CpuRequirement,
    pub warnings: Vec<AnalysisWarning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    Elf,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryType {
    Executable,
    PieExecutable,
    SharedLibrary,
    Relocatable,
    Core,
    Other,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
    Other(u16),
}
impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_64 => f.write_str("x86_64"),
            Self::Aarch64 => f.write_str("aarch64"),
            Self::Other(n) => write!(f, "other (e_machine={n})"),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    Little,
    Big,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Linking {
    Static,
    Dynamic,
    NotApplicable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LibcFamily {
    Glibc,
    Musl,
    Other,
    None,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibcInfo {
    pub family: LibcFamily,
    pub evidence: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRequirement {
    pub library: String,
    pub version: String,
    pub symbols: Vec<String>,
    /// GNU VER_FLG_WEAK: absence of the version alone is not a fatal loader error.
    /// This does not establish the binding or fallback behavior of its symbols.
    pub weak: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlibcRequirement {
    pub minimum: LibcVersion,
    pub causing_symbols: Vec<String>,
}

/// Numeric major.minor[.patch], serialized as a string. Missing patch equals zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LibcVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}
impl FromStr for LibcVersion {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split('.').collect();
        if !(2..=3).contains(&parts.len())
            || parts
                .iter()
                .any(|p| p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()))
        {
            return Err(format!(
                "invalid version {s:?}; expected major.minor[.patch]"
            ));
        }
        let number = |s: &str| s.parse().map_err(|_| format!("invalid version {s:?}"));
        Ok(Self {
            major: number(parts[0])?,
            minor: number(parts[1])?,
            patch: if parts.len() == 3 {
                number(parts[2])?
            } else {
                0
            },
        })
    }
}
impl fmt::Display for LibcVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)?;
        if self.patch != 0 {
            write!(f, ".{}", self.patch)?;
        }
        Ok(())
    }
}
impl TryFrom<String> for LibcVersion {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        s.parse()
    }
}
impl From<LibcVersion> for String {
    fn from(v: LibcVersion) -> Self {
        v.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum X86Isa {
    #[serde(rename = "x86-64")]
    Baseline,
    #[serde(rename = "x86-64-v2")]
    V2,
    #[serde(rename = "x86-64-v3")]
    V3,
    #[serde(rename = "x86-64-v4")]
    V4,
}
impl fmt::Display for X86Isa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Baseline => "x86-64",
            Self::V2 => "x86-64-v2",
            Self::V3 => "x86-64-v3",
            Self::V4 => "x86-64-v4",
        })
    }
}
impl FromStr for X86Isa {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "x86-64" | "x86-64-v1" => Ok(Self::Baseline),
            "x86-64-v2" => Ok(Self::V2),
            "x86-64-v3" => Ok(Self::V3),
            "x86-64-v4" => Ok(Self::V4),
            _ => Err("expected x86-64, x86-64-v2, x86-64-v3 or x86-64-v4".into()),
        }
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuRequirement {
    pub x86_64_isa: Option<X86Isa>,
    pub unknown_isa_bits: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisWarning {
    pub code: String,
    pub message: String,
}
impl AnalysisWarning {
    pub(crate) fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compatibility {
    Compatible,
    Incompatible,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintResult {
    pub constraint: String,
    pub status: Compatibility,
    /// Whether an unknown result prevents a positive verdict within this check's scope.
    pub required: bool,
    pub reason: String,
    pub causing_symbols: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityReport {
    pub target: String,
    pub name: String,
    pub status: Compatibility,
    pub constraints: Vec<ConstraintResult>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inspection {
    pub schema_version: u32,
    pub binary: BinaryReport,
    pub compatibility: Vec<CompatibilityReport>,
}

// Recognized glibc runtime providers; independent of the input binary format.
pub(crate) fn glibc_object(library: &str) -> bool {
    matches!(
        library,
        "libc.so.6"
            | "libm.so.6"
            | "libmvec.so.1"
            | "libpthread.so.0"
            | "libdl.so.2"
            | "librt.so.1"
            | "libresolv.so.2"
            | "libutil.so.1"
            | "libanl.so.1"
            | "libBrokenLocale.so.1"
            | "libthread_db.so.1"
            | "ld-linux-x86-64.so.2"
            | "ld-linux-aarch64.so.1"
            | "ld-linux.so.2"
            | "ld-linux-armhf.so.3"
            | "ld64.so.1"
            | "ld64.so.2"
    )
}
