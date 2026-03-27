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
use std::fmt;

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

    /// Parse the configured flow expression into a typed AST.
    ///
    /// # Errors
    ///
    /// Returns a template validation error when the flow expression is invalid.
    pub fn parse_flow(&self) -> crate::Result<Option<FlowExpression>> {
        let parsed = self
            .flow
            .as_deref()
            .map(FlowExpression::parse)
            .transpose()
            .map_err(|reason| crate::Error::TemplateValidation {
                id: self.id.clone(),
                reason,
            })?;

        if let Some(expression) = &parsed {
            self.validate_flow_expression(expression)?;
        }

        Ok(parsed)
    }

    /// Resolve this template against parent templates referenced via `extends`.
    ///
    /// Child scalar fields override inherited values. Map-like fields merge with
    /// child keys taking precedence. Collection fields such as requests and
    /// workflows inherit the parent value only when the child leaves them empty.
    ///
    /// # Errors
    ///
    /// Returns a template validation error when a parent is missing, the
    /// inheritance chain contains a cycle, or the resolved flow expression is invalid.
    pub fn resolve_inheritance(
        &self,
        templates: &HashMap<String, Template>,
    ) -> crate::Result<Template> {
        let mut stack = Vec::new();
        self.resolve_inheritance_inner(templates, &mut stack)
    }

    fn resolve_inheritance_inner(
        &self,
        templates: &HashMap<String, Template>,
        stack: &mut Vec<String>,
    ) -> crate::Result<Template> {
        let Some(parent_id) = self.extends.as_deref() else {
            return Ok(self.clone());
        };

        if stack.iter().any(|id| id == &self.id) {
            stack.push(self.id.clone());
            return Err(crate::Error::TemplateValidation {
                id: self.id.clone(),
                reason: format!(
                    "template inheritance cycle detected: {}",
                    stack.join(" -> ")
                ),
            });
        }

        let parent = templates
            .get(parent_id)
            .ok_or_else(|| crate::Error::TemplateValidation {
                id: self.id.clone(),
                reason: format!("parent template '{parent_id}' was not found"),
            })?;

        stack.push(self.id.clone());
        let resolved_parent = parent.resolve_inheritance_inner(templates, stack)?;
        stack.pop();

        self.merge_with_parent(&resolved_parent)
    }

    fn merge_with_parent(&self, parent: &Template) -> crate::Result<Template> {
        let protocol = if matches!(self.protocol, Protocol::Http)
            && !matches!(parent.protocol, Protocol::Http)
        {
            parent.protocol
        } else {
            self.protocol
        };

        let resolved = Template {
            id: self.id.clone(),
            ir_version: self.ir_version.max(parent.ir_version),
            extends: None,
            imports: merge_named_items(&parent.imports, &self.imports, |item| &item.id),
            info: self.info.clone().merge(parent.info.clone()),
            requests: if self.requests.is_empty() {
                parent.requests.clone()
            } else {
                self.requests.clone()
            },
            protocol,
            self_contained: self.self_contained || parent.self_contained,
            variables: merge_maps(&parent.variables, &self.variables),
            cli_variables: merge_maps(&parent.cli_variables, &self.cli_variables),
            source_path: self
                .source_path
                .clone()
                .or_else(|| parent.source_path.clone()),
            flow: self.flow.clone().or_else(|| parent.flow.clone()),
            workflows: if self.workflows.is_empty() {
                parent.workflows.clone()
            } else {
                self.workflows.clone()
            },
            karyx_extensions: merge_maps(&parent.karyx_extensions, &self.karyx_extensions),
            parallel_groups: if self.parallel_groups.is_empty() {
                parent.parallel_groups.clone()
            } else {
                self.parallel_groups.clone()
            },
        };

        resolved.parse_flow()?;
        Ok(resolved)
    }

    fn validate_flow_expression(&self, expression: &FlowExpression) -> crate::Result<()> {
        expression.validate_for_template(self)
    }
}

fn merge_maps<T: Clone>(
    parent: &HashMap<String, T>,
    child: &HashMap<String, T>,
) -> HashMap<String, T> {
    let mut merged = parent.clone();
    merged.extend(child.clone());
    merged
}

fn merge_named_items<T: Clone, F>(parent: &[T], child: &[T], key: F) -> Vec<T>
where
    F: Fn(&T) -> &str,
{
    let mut merged = Vec::with_capacity(parent.len() + child.len());
    let mut seen = std::collections::HashSet::new();

    for item in parent.iter().chain(child.iter()) {
        let name = key(item);
        if seen.insert(name.to_string()) {
            merged.push(item.clone());
        }
    }

    merged
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

/// Parsed Nuclei-style flow expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowExpression {
    /// A protocol invocation such as `http(1)`.
    Call { protocol: String, request: usize },
    /// Logical negation.
    Not(Box<FlowExpression>),
    /// Logical conjunction.
    And(Box<FlowExpression>, Box<FlowExpression>),
    /// Logical disjunction.
    Or(Box<FlowExpression>, Box<FlowExpression>),
}

impl FlowExpression {
    /// Parse a flow expression.
    ///
    /// # Errors
    ///
    /// Returns a human-readable parse error when the input is invalid.
    pub fn parse(input: &str) -> std::result::Result<Self, String> {
        let mut parser = FlowParser::new(input);
        let expression = parser.parse_expression()?;
        parser.expect_end()?;
        Ok(expression)
    }

    /// Return whether this flow expression allows `request_index` to run given
    /// the currently known per-request match results.
    pub fn allows_request(
        &self,
        request_index: usize,
        request_results: &HashMap<usize, bool>,
    ) -> bool {
        if !self.mentions_request(request_index) {
            return false;
        }

        match self.request_gate_value(request_index, request_results) {
            FlowGate::Known(result) => result,
            FlowGate::Pending => false,
        }
    }

    /// Validate that this flow expression only references the current
    /// template's protocol and in-range request numbers.
    pub fn validate_for_template(&self, template: &Template) -> crate::Result<()> {
        self.validate_calls(template)
    }

    fn validate_calls(&self, template: &Template) -> crate::Result<()> {
        match self {
            Self::Call { protocol, request } => {
                let expected_protocol = template.protocol.name();
                if !protocol.eq_ignore_ascii_case(expected_protocol) {
                    return Err(crate::Error::TemplateValidation {
                        id: template.id.clone(),
                        reason: format!(
                            "flow references protocol '{protocol}', but template protocol is '{expected_protocol}'. Use {expected_protocol}(N) or move the request to a {protocol} template."
                        ),
                    });
                }

                if *request == 0 {
                    return Err(crate::Error::TemplateValidation {
                        id: template.id.clone(),
                        reason: "flow request indices are 1-based. Replace '(0)' with '(1)' for the first request.".to_string(),
                    });
                }

                if *request > template.requests.len() {
                    return Err(crate::Error::TemplateValidation {
                        id: template.id.clone(),
                        reason: format!(
                            "flow references request {request}, but template defines only {} request(s). Fix the flow expression or add the missing request.",
                            template.requests.len()
                        ),
                    });
                }
                Ok(())
            }
            Self::Not(expr) => expr.validate_calls(template),
            Self::And(left, right) | Self::Or(left, right) => {
                left.validate_calls(template)?;
                right.validate_calls(template)
            }
        }
    }

    fn mentions_request(&self, request_index: usize) -> bool {
        match self {
            Self::Call { request, .. } => request.saturating_sub(1) == request_index,
            Self::Not(expr) => expr.mentions_request(request_index),
            Self::And(left, right) | Self::Or(left, right) => {
                left.mentions_request(request_index) || right.mentions_request(request_index)
            }
        }
    }

    fn request_gate_value(
        &self,
        request_index: usize,
        request_results: &HashMap<usize, bool>,
    ) -> FlowGate {
        match self {
            Self::Call { request, .. } => {
                if request.saturating_sub(1) == request_index {
                    FlowGate::Known(true)
                } else {
                    FlowGate::Pending
                }
            }
            Self::Not(expr) => match expr.request_gate_value(request_index, request_results) {
                FlowGate::Known(result) => FlowGate::Known(!result),
                FlowGate::Pending => FlowGate::Pending,
            },
            Self::And(left, right) => {
                if left.mentions_request(request_index) {
                    left.request_gate_value(request_index, request_results)
                } else if right.mentions_request(request_index) {
                    match left.evaluate(request_results) {
                        FlowGate::Known(true) => {
                            right.request_gate_value(request_index, request_results)
                        }
                        FlowGate::Known(false) => FlowGate::Known(false),
                        FlowGate::Pending => FlowGate::Pending,
                    }
                } else {
                    FlowGate::Known(false)
                }
            }
            Self::Or(left, right) => {
                if left.mentions_request(request_index) {
                    left.request_gate_value(request_index, request_results)
                } else if right.mentions_request(request_index) {
                    match left.evaluate(request_results) {
                        FlowGate::Known(true) => FlowGate::Known(false),
                        FlowGate::Known(false) => {
                            right.request_gate_value(request_index, request_results)
                        }
                        FlowGate::Pending => FlowGate::Pending,
                    }
                } else {
                    FlowGate::Known(false)
                }
            }
        }
    }

    fn evaluate(&self, request_results: &HashMap<usize, bool>) -> FlowGate {
        match self {
            Self::Call { request, .. } => request_results
                .get(&request.saturating_sub(1))
                .copied()
                .map_or(FlowGate::Pending, FlowGate::Known),
            Self::Not(expr) => match expr.evaluate(request_results) {
                FlowGate::Known(result) => FlowGate::Known(!result),
                FlowGate::Pending => FlowGate::Pending,
            },
            Self::And(left, right) => match left.evaluate(request_results) {
                FlowGate::Known(false) => FlowGate::Known(false),
                FlowGate::Known(true) => right.evaluate(request_results),
                FlowGate::Pending => FlowGate::Pending,
            },
            Self::Or(left, right) => match left.evaluate(request_results) {
                FlowGate::Known(true) => FlowGate::Known(true),
                FlowGate::Known(false) => right.evaluate(request_results),
                FlowGate::Pending => FlowGate::Pending,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowGate {
    Known(bool),
    Pending,
}

impl fmt::Display for FlowExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Call { protocol, request } => write!(f, "{protocol}({request})"),
            Self::Not(expr) => write!(f, "!({expr})"),
            Self::And(left, right) => write!(f, "({left} && {right})"),
            Self::Or(left, right) => write!(f, "({left} || {right})"),
        }
    }
}

#[derive(Debug, Clone)]
struct FlowParser<'a> {
    input: &'a str,
    chars: Vec<char>,
    pos: usize,
}

impl<'a> FlowParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            chars: input.chars().collect(),
            pos: 0,
        }
    }

    fn parse_expression(&mut self) -> std::result::Result<FlowExpression, String> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> std::result::Result<FlowExpression, String> {
        let mut expr = self.parse_and()?;
        loop {
            self.skip_ws();
            if self.consume_str("||") {
                expr = FlowExpression::Or(Box::new(expr), Box::new(self.parse_and()?));
            } else {
                return Ok(expr);
            }
        }
    }

    fn parse_and(&mut self) -> std::result::Result<FlowExpression, String> {
        let mut expr = self.parse_unary()?;
        loop {
            self.skip_ws();
            if self.consume_str("&&") {
                expr = FlowExpression::And(Box::new(expr), Box::new(self.parse_unary()?));
            } else {
                return Ok(expr);
            }
        }
    }

    fn parse_unary(&mut self) -> std::result::Result<FlowExpression, String> {
        self.skip_ws();
        if self.consume_char('!') {
            return Ok(FlowExpression::Not(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> std::result::Result<FlowExpression, String> {
        self.skip_ws();
        if self.consume_char('(') {
            let expr = self.parse_expression()?;
            self.skip_ws();
            if !self.consume_char(')') {
                return Err("missing closing ')' in flow expression".to_string());
            }
            return Ok(expr);
        }

        let protocol = self.parse_identifier()?;
        self.skip_ws();
        if !self.consume_char('(') {
            return Err(format!("expected '(' after protocol '{protocol}'"));
        }

        self.skip_ws();
        let request = self.parse_number()?;
        self.skip_ws();
        if !self.consume_char(')') {
            return Err(format!("expected ')' after {protocol}({request}"));
        }

        Ok(FlowExpression::Call { protocol, request })
    }

    fn parse_identifier(&mut self) -> std::result::Result<String, String> {
        self.skip_ws();
        let start = self.pos;
        while self
            .chars
            .get(self.pos)
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        {
            self.pos += 1;
        }

        if start == self.pos {
            return Err(format!(
                "expected protocol identifier at byte {} in '{}'",
                self.pos, self.input
            ));
        }

        Ok(self.chars[start..self.pos].iter().collect())
    }

    fn parse_number(&mut self) -> std::result::Result<usize, String> {
        let start = self.pos;
        while self.chars.get(self.pos).is_some_and(char::is_ascii_digit) {
            self.pos += 1;
        }

        if start == self.pos {
            return Err(format!(
                "expected request index at byte {} in '{}'",
                self.pos, self.input
            ));
        }

        self.chars[start..self.pos]
            .iter()
            .collect::<String>()
            .parse::<usize>()
            .map_err(|_| "request index is out of range".to_string())
    }

    fn expect_end(&mut self) -> std::result::Result<(), String> {
        self.skip_ws();
        if self.pos == self.chars.len() {
            Ok(())
        } else {
            Err(format!(
                "unexpected trailing input starting at byte {} in '{}'",
                self.pos, self.input
            ))
        }
    }

    fn skip_ws(&mut self) {
        while self
            .chars
            .get(self.pos)
            .is_some_and(|ch| ch.is_whitespace())
        {
            self.pos += 1;
        }
    }

    fn consume_char(&mut self, expected: char) -> bool {
        if self.chars.get(self.pos).copied() == Some(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn consume_str(&mut self, expected: &str) -> bool {
        let expected_chars: Vec<_> = expected.chars().collect();
        if self.chars[self.pos..].starts_with(&expected_chars) {
            self.pos += expected_chars.len();
            true
        } else {
            false
        }
    }
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

    #[test]
    fn parses_nested_flow_expression() {
        let template = Template {
            id: "flow-test".to_string(),
            ir_version: default_ir_version(),
            extends: None,
            imports: Vec::new(),
            info: TemplateInfo {
                name: "Flow Test".to_string(),
                author: vec![],
                severity: Severity::Info,
                description: None,
                reference: vec![],
                tags: vec![],
                metadata: TemplateMeta::default(),
            },
            requests: vec![RequestDef::default(), RequestDef::default(), RequestDef::default()],
            protocol: Protocol::Http,
            self_contained: false,
            variables: HashMap::new(),
            cli_variables: HashMap::new(),
            source_path: None,
            flow: Some("http(1) && (!http(2) || http(3))".to_string()),
            workflows: Vec::new(),
            karyx_extensions: HashMap::new(),
            parallel_groups: Vec::new(),
        };

        let flow = template.parse_flow().unwrap().unwrap();
        assert_eq!(flow.to_string(), "(http(1) && (!(http(2)) || http(3)))");
    }

    #[test]
    fn invalid_flow_returns_validation_error() {
        let template = Template {
            id: "bad-flow".to_string(),
            ir_version: default_ir_version(),
            extends: None,
            imports: Vec::new(),
            info: TemplateInfo {
                name: "Bad Flow".to_string(),
                author: vec![],
                severity: Severity::Info,
                description: None,
                reference: vec![],
                tags: vec![],
                metadata: TemplateMeta::default(),
            },
            requests: vec![RequestDef::default()],
            protocol: Protocol::Http,
            self_contained: false,
            variables: HashMap::new(),
            cli_variables: HashMap::new(),
            source_path: None,
            flow: Some("http(1 && dns(2)".to_string()),
            workflows: Vec::new(),
            karyx_extensions: HashMap::new(),
            parallel_groups: Vec::new(),
        };

        let error = template.parse_flow().unwrap_err();
        assert!(matches!(error, crate::Error::TemplateValidation { .. }));
    }

    #[test]
    fn flow_validation_rejects_wrong_protocol() {
        let template = Template {
            id: "bad-flow-protocol".to_string(),
            ir_version: default_ir_version(),
            extends: None,
            imports: Vec::new(),
            info: TemplateInfo {
                name: "Bad Flow Protocol".to_string(),
                author: vec![],
                severity: Severity::Info,
                description: None,
                reference: vec![],
                tags: vec![],
                metadata: TemplateMeta::default(),
            },
            requests: vec![RequestDef::default()],
            protocol: Protocol::Http,
            self_contained: false,
            variables: HashMap::new(),
            cli_variables: HashMap::new(),
            source_path: None,
            flow: Some("dns(1)".to_string()),
            workflows: Vec::new(),
            karyx_extensions: HashMap::new(),
            parallel_groups: Vec::new(),
        };

        let error = template.parse_flow().unwrap_err().to_string();
        assert!(error.contains("template protocol is 'http'"));
    }

    #[test]
    fn flow_allows_request_uses_prior_results() {
        let flow = FlowExpression::parse("http(1) && http(2)").unwrap();

        assert!(flow.allows_request(0, &HashMap::new()));
        assert!(!flow.allows_request(1, &HashMap::new()));

        let prior = HashMap::from([(0usize, true)]);
        assert!(flow.allows_request(1, &prior));

        let prior = HashMap::from([(0usize, false)]);
        assert!(!flow.allows_request(1, &prior));
    }

    #[test]
    fn resolve_template_inheritance_merges_parent_fields() {
        let parent = Template {
            id: "base".to_string(),
            ir_version: default_ir_version(),
            extends: None,
            imports: vec![TemplateImport {
                id: "shared".to_string(),
                alias: None,
            }],
            info: TemplateInfo {
                name: "Base".to_string(),
                author: vec!["alice".to_string()],
                severity: Severity::High,
                description: Some("parent".to_string()),
                reference: vec!["https://example.com/base".to_string()],
                tags: vec!["tech".to_string()],
                metadata: TemplateMeta {
                    cve_id: vec!["CVE-2026-0001".to_string()],
                    cwe_id: vec![],
                    cvss_score: Some(8.8),
                    extra: HashMap::from([(
                        "family".to_string(),
                        serde_json::Value::String("base".to_string()),
                    )]),
                },
            },
            requests: vec![RequestDef {
                method: "GET".to_string(),
                ..RequestDef::default()
            }],
            protocol: Protocol::Dns,
            self_contained: true,
            variables: HashMap::from([("shared".to_string(), "parent".to_string())]),
            cli_variables: HashMap::new(),
            source_path: Some("base.yaml".to_string()),
            flow: Some("dns(1)".to_string()),
            workflows: vec![Workflow { steps: vec![] }],
            karyx_extensions: HashMap::from([("base".to_string(), serde_json::Value::Bool(true))]),
            parallel_groups: vec![ParallelGroup {
                request_indices: vec![0],
            }],
        };

        let child = Template {
            id: "child".to_string(),
            ir_version: default_ir_version(),
            extends: Some("base".to_string()),
            imports: vec![TemplateImport {
                id: "child-only".to_string(),
                alias: None,
            }],
            info: TemplateInfo {
                name: String::new(),
                author: vec!["bob".to_string()],
                severity: Severity::Unknown,
                description: None,
                reference: vec!["https://example.com/child".to_string()],
                tags: vec!["detect".to_string()],
                metadata: TemplateMeta {
                    cve_id: Vec::new(),
                    cwe_id: vec!["CWE-79".to_string()],
                    cvss_score: None,
                    extra: HashMap::from([(
                        "family".to_string(),
                        serde_json::Value::String("child".to_string()),
                    )]),
                },
            },
            requests: Vec::new(),
            protocol: Protocol::Http,
            self_contained: false,
            variables: HashMap::from([("shared".to_string(), "child".to_string())]),
            cli_variables: HashMap::from([("runtime".to_string(), "set".to_string())]),
            source_path: None,
            flow: None,
            workflows: Vec::new(),
            karyx_extensions: HashMap::from([("child".to_string(), serde_json::Value::Bool(true))]),
            parallel_groups: Vec::new(),
        };

        let templates = HashMap::from([
            (parent.id.clone(), parent.clone()),
            (child.id.clone(), child.clone()),
        ]);
        let resolved = child.resolve_inheritance(&templates).unwrap();

        assert_eq!(resolved.extends, None);
        assert_eq!(resolved.info.name, "Base");
        assert_eq!(resolved.info.author, vec!["alice", "bob"]);
        assert_eq!(resolved.info.severity, Severity::High);
        assert_eq!(resolved.requests.len(), 1);
        assert_eq!(resolved.protocol, Protocol::Dns);
        assert_eq!(
            resolved.variables.get("shared").map(String::as_str),
            Some("child")
        );
        assert_eq!(resolved.flow.as_deref(), Some("dns(1)"));
        assert_eq!(resolved.parallel_groups.len(), 1);
        assert_eq!(resolved.imports.len(), 2);
        assert_eq!(
            resolved
                .karyx_extensions
                .get("child")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn resolve_template_inheritance_detects_cycles() {
        let template_a = Template {
            id: "a".to_string(),
            ir_version: default_ir_version(),
            extends: Some("b".to_string()),
            imports: Vec::new(),
            info: TemplateInfo {
                name: "A".to_string(),
                author: vec![],
                severity: Severity::Info,
                description: None,
                reference: vec![],
                tags: vec![],
                metadata: TemplateMeta::default(),
            },
            requests: vec![RequestDef::default()],
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

        let template_b = Template {
            id: "b".to_string(),
            extends: Some("a".to_string()),
            ..template_a.clone()
        };

        let templates = HashMap::from([
            (template_a.id.clone(), template_a.clone()),
            (template_b.id.clone(), template_b.clone()),
        ]);

        let error = template_a.resolve_inheritance(&templates).unwrap_err();
        assert!(matches!(error, crate::Error::TemplateValidation { .. }));
    }
}
