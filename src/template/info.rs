use crate::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Template metadata — who wrote it, what it detects, how severe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    /// Human-readable template title.
    pub name: String,
    /// Template author identifiers.
    pub author: Vec<String>,
    /// Declared severity of the template.
    #[serde(default)]
    pub severity: Severity,
    /// Optional descriptive summary.
    #[serde(default)]
    pub description: Option<String>,
    /// Reference URLs for additional context.
    #[serde(default)]
    pub reference: Vec<String>,
    /// Search and classification tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Extended classification metadata.
    #[serde(default)]
    pub metadata: TemplateMeta,
}

/// Extended metadata (CVE IDs, CVSS, etc.)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemplateMeta {
    /// Associated CVE identifiers.
    #[serde(default)]
    pub cve_id: Vec<String>,
    /// Associated CWE identifiers.
    #[serde(default)]
    pub cwe_id: Vec<String>,
    /// Optional CVSS score.
    #[serde(default)]
    pub cvss_score: Option<f64>,
    /// Additional unstructured metadata.
    #[serde(default)]
    pub extra: HashMap<String, serde_json::Value>,
}
