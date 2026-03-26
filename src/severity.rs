//! Severity classification for vulnerability findings.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity levels compatible with Nuclei's severity classification.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Severity {
    /// Informational detection with no direct security impact.
    Info,
    /// Low-impact issue.
    Low,
    /// Medium-impact issue.
    Medium,
    /// High-impact issue.
    High,
    /// Critical-impact issue.
    Critical,
    /// Severity is missing or unknown.
    #[default]
    Unknown,
}

impl Severity {
    /// Return the canonical lowercase severity label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
