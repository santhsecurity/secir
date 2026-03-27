//! Finding types and helpers used to represent scan results across the runtime.
//!
//! This module provides the core data structures for security scan results,
//! including the [`Finding`] struct which represents a confirmed vulnerability
//! or detection, and [`FindingKind`] for classification.

use crate::transport::RequestSpec;
use crate::{Severity, TemplateId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single finding produced by matching a template against a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct Finding {
    /// Which template produced this finding.
    pub template_id: TemplateId,

    /// Human-readable template name.
    #[serde(rename = "template-name")]
    pub template_name: String,

    /// Source template file path.
    #[serde(
        default,
        rename = "template-path",
        skip_serializing_if = "Option::is_none"
    )]
    pub template_path: Option<String>,

    /// The target URL that was scanned.
    #[serde(alias = "host")]
    pub target: String,

    /// Severity of the finding.
    pub severity: Severity,

    /// What kind of finding this is.
    #[serde(rename = "type")]
    pub kind: FindingKind,

    /// The specific matched value(s) that triggered the finding.
    pub matched_values: Vec<String>,

    /// Data extracted by extractors (name → value).
    #[serde(default)]
    pub extracted: HashMap<String, String>,

    /// The matched URL (may differ from target due to path expansion).
    pub matched_at: String,

    /// Raw HTTP request that produced this finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,

    /// Raw HTTP response that produced this finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,

    /// Reproducible curl command.
    #[serde(
        default,
        rename = "curl-command",
        skip_serializing_if = "Option::is_none"
    )]
    pub curl_command: Option<String>,

    /// Which specific matcher fired.
    #[serde(
        default,
        rename = "matcher-name",
        skip_serializing_if = "Option::is_none"
    )]
    pub matcher_name: Option<String>,

    /// Protocol type that produced the finding.
    #[serde(default, rename = "protocol")]
    pub protocol: Option<String>,

    /// Timestamp of the finding.
    pub timestamp: DateTime<Utc>,

    /// Tags inherited from the template.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Template description (for reporting).
    #[serde(default)]
    pub description: Option<String>,

    /// Reference URLs.
    #[serde(default, alias = "reference")]
    pub references: Vec<String>,

    /// CVE IDs associated with this finding.
    #[serde(default)]
    pub cve_ids: Vec<String>,

    /// Statistical confidence score (0.0 to 1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,

    /// Internal metadata used to replay and verify findings.
    #[serde(skip)]
    #[cfg_attr(feature = "json-schema", schemars(skip))]
    pub verification: Option<FindingVerification>,
}

/// Calculate statistical confidence score based on matcher types and hit ratios.
///
/// The confidence score is a heuristic value between 0.0 and 1.0 that indicates
/// how reliable a template's findings are expected to be. Higher confidence
/// is assigned to templates with:
///
/// - Multiple AND conditions combined with extractors (0.95)
/// - Status + word matchers with AND condition (0.85)
/// - Regex patterns with capture groups (0.80)
/// - Multiple word matchers with AND condition (0.70)
/// - Simple word matchers (0.50)
///
/// # Arguments
///
/// * `template` - The template to analyze for confidence scoring
///
/// # Returns
///
/// A confidence score between 0.0 and 1.0
///
/// # Example
///
/// ```
/// use secir::{Template, TemplateInfo, Severity, calculate_confidence};
/// use std::collections::HashMap;
///
/// let template = Template {
///     id: "test-template".to_string(),
///     ir_version: 1,
///     extends: None,
///     imports: vec![],
///     info: TemplateInfo {
///         name: "Test".to_string(),
///         author: vec![],
///         severity: Severity::Info,
///         description: None,
///         reference: vec![],
///         tags: vec!["tech".to_string()],
///         metadata: Default::default(),
///     },
///     requests: vec![],
///     protocol: secir::Protocol::Http,
///     self_contained: false,
///     variables: HashMap::new(),
///     cli_variables: HashMap::new(),
///     source_path: None,
///     flow: None,
///     workflows: vec![],
///     karyx_extensions: HashMap::new(),
///     parallel_groups: vec![],
/// };
///
/// let confidence = calculate_confidence(&template);
/// assert!((0.0..=1.0).contains(&confidence));
/// ```
pub fn calculate_confidence(template: &crate::Template) -> f64 {
    let mut has_extractor = false;
    let mut has_word = false;
    let mut has_regex_with_groups = false;
    let mut has_multiple_and = false;
    let mut multiple_word_and = false;
    let mut status_and_word_and = false;

    for req in &template.requests {
        if !req.extractors.is_empty() {
            has_extractor = true;
        }

        let is_and = req.matchers_condition == crate::MatcherCondition::And;
        if is_and && req.matchers.len() > 1 {
            has_multiple_and = true;
        }

        let mut word_count = 0;
        let mut local_has_status = false;
        let mut local_has_word = false;

        for m in &req.matchers {
            match m.kind {
                crate::MatcherKind::Word => {
                    has_word = true;
                    local_has_word = true;
                    word_count += 1;
                }
                crate::MatcherKind::Regex => {
                    if m.values.iter().any(|v| v.contains('(') && v.contains(')')) {
                        has_regex_with_groups = true;
                    }
                }
                crate::MatcherKind::Status => {
                    local_has_status = true;
                }
                _ => {}
            }
        }

        if is_and && word_count > 1 {
            multiple_word_and = true;
        }
        if is_and && local_has_status && local_has_word {
            status_and_word_and = true;
        }
    }

    if has_multiple_and && has_extractor {
        return 0.95;
    }
    if status_and_word_and {
        return 0.85;
    }
    if has_regex_with_groups {
        return 0.8;
    }
    if multiple_word_and {
        return 0.7;
    }
    if has_word {
        return 0.5;
    }

    0.5
}

/// Internal metadata for replaying and verifying findings.
///
/// This struct stores the necessary information to reproduce a finding
/// for verification purposes, including the exact request specification
/// and any variables that were in scope.
#[derive(Debug, Clone)]
pub struct FindingVerification {
    pub request_spec: RequestSpec,
    pub request_index: usize,
    pub variables: HashMap<String, String>,
}

/// Classification of what the finding represents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum FindingKind {
    /// A confirmed vulnerability.
    Vulnerability,
    /// A misconfiguration.
    Misconfiguration,
    /// An exposed service or panel.
    Exposure,
    /// Technology detection (informational).
    TechDetect,
    /// Default or weak credentials.
    DefaultCredentials,
    /// Information disclosure.
    InfoDisclosure,
    /// File or directory found.
    FileDiscovery,
    /// Unclassified.
    Other,
}

impl Finding {
    /// Create a finding with the required identity fields and a current timestamp.
    #[must_use]
    pub fn new(
        template_id: TemplateId,
        template_name: String,
        target: String,
        severity: Severity,
        matched_at: String,
    ) -> Self {
        Self {
            template_id,
            template_name,
            template_path: None,
            target,
            severity,
            kind: FindingKind::Other,
            matched_values: Vec::new(),
            extracted: HashMap::new(),
            matched_at,
            request: None,
            response: None,
            curl_command: None,
            matcher_name: None,
            protocol: None,
            timestamp: Utc::now(),
            tags: Vec::new(),
            description: None,
            references: Vec::new(),
            cve_ids: Vec::new(),
            confidence: None,
            verification: None,
        }
    }

    /// Create a finding pre-populated from a template's metadata.
    ///
    /// This is the standard constructor for protocol scanners — it sets
    /// tags, description, references, CVE IDs, and finding kind from the
    /// template, eliminating 6 lines of boilerplate per finding site.
    #[must_use]
    pub fn from_template(
        template: &crate::Template,
        target: String,
        matched_at: String,
        matched_values: Vec<String>,
    ) -> Self {
        let mut finding = Self::new(
            template.id.clone(),
            template.info.name.clone(),
            target,
            template.info.severity,
            matched_at,
        );
        finding.matched_values = matched_values;
        finding.tags.clone_from(&template.info.tags);
        finding.description.clone_from(&template.info.description);
        finding.references.clone_from(&template.info.reference);
        finding.cve_ids.clone_from(&template.info.metadata.cve_id);
        finding.kind = template.classify();
        finding.protocol = Some(format!("{:?}", template.protocol).to_ascii_lowercase());
        finding.confidence = Some(calculate_confidence(template));
        finding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_serializes() {
        let mut finding = Finding::new(
            "CVE-2021-44228".to_string(),
            "Log4j RCE".to_string(),
            "https://example.com".to_string(),
            Severity::Critical,
            "https://example.com/api".to_string(),
        );
        finding.references = vec!["https://example.com/ref".to_string()];

        let json = serde_json::to_value(&finding).expect("operation should succeed");
        assert_eq!(json["template-name"], "Log4j RCE");
        assert_eq!(json["target"], "https://example.com");
        assert_eq!(json["type"], "other");
        assert_eq!(json["references"][0], "https://example.com/ref");
        assert!(json.get("template_name").is_none());
        assert!(json.get("host").is_none());
        assert!(json.get("kind").is_none());
        assert!(json.get("reference").is_none());
    }

    #[test]
    fn finding_deserializes_legacy_aliases() {
        let json = serde_json::json!({
            "template_id": "CVE-2021-44228",
            "template-name": "Log4j RCE",
            "host": "https://example.com",
            "severity": "critical",
            "type": "other",
            "matched_values": [],
            "extracted": {},
            "matched_at": "https://example.com/api",
            "timestamp": "2024-01-01T00:00:00Z",
            "tags": [],
            "description": null,
            "reference": ["https://example.com/ref"],
            "cve_ids": []
        });

        let finding: Finding = serde_json::from_value(json).expect("operation should succeed");
        assert_eq!(finding.template_name, "Log4j RCE");
        assert_eq!(finding.target, "https://example.com");
        assert_eq!(finding.kind, FindingKind::Other);
        assert_eq!(
            finding.references,
            vec!["https://example.com/ref".to_string()]
        );
    }

    #[test]
    fn finding_kind_kebab_case() {
        let json =
            serde_json::to_string(&FindingKind::TechDetect).expect("operation should succeed");
        assert_eq!(json, "\"tech-detect\"");

        let roundtripped: FindingKind =
            serde_json::from_str("\"default-credentials\"").expect("operation should succeed");
        assert_eq!(roundtripped, FindingKind::DefaultCredentials);
    }
}
