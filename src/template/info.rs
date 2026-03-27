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

impl TemplateInfo {
    pub(crate) fn merge(self, parent: Self) -> Self {
        Self {
            name: if self.name.is_empty() {
                parent.name
            } else {
                self.name
            },
            author: merge_string_lists(parent.author, self.author),
            severity: if matches!(self.severity, Severity::Unknown) {
                parent.severity
            } else {
                self.severity
            },
            description: self.description.or(parent.description),
            reference: merge_string_lists(parent.reference, self.reference),
            tags: merge_string_lists(parent.tags, self.tags),
            metadata: self.metadata.merge(parent.metadata),
        }
    }
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

impl TemplateMeta {
    fn merge(self, parent: Self) -> Self {
        let mut extra = parent.extra;
        extra.extend(self.extra);

        Self {
            cve_id: merge_string_lists(parent.cve_id, self.cve_id),
            cwe_id: merge_string_lists(parent.cwe_id, self.cwe_id),
            cvss_score: self.cvss_score.or(parent.cvss_score),
            extra,
        }
    }
}

fn merge_string_lists(parent: Vec<String>, child: Vec<String>) -> Vec<String> {
    let mut merged = Vec::with_capacity(parent.len() + child.len());
    let mut seen = std::collections::HashSet::new();

    for value in parent.into_iter().chain(child) {
        if seen.insert(value.clone()) {
            merged.push(value);
        }
    }

    merged
}
