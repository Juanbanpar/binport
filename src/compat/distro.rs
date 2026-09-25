use crate::model::{Architecture, LibcFamily, LibcVersion};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistroRelease {
    pub id: String,
    pub name: String,
    pub version: String,
    pub glibc: LibcVersion,
    pub libc: LibcFamily,
    pub architectures: Vec<Architecture>,
    pub x86_64_interpreter: String,
    pub aarch64_interpreter: String,
    pub source: String,
    pub verified: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Database {
    release: Vec<DistroRelease>,
}

/// Embedded release baselines, never fetched from a network or inferred from the host.
pub fn built_in() -> Result<Vec<DistroRelease>, toml::de::Error> {
    Ok(toml::from_str::<Database>(include_str!("../../data/distros.toml"))?.release)
}
