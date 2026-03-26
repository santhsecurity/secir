//! Template composition — multi-format, multi-protocol, conditional chains.
//!
//! This is what makes Karyx categorically different from Nuclei.
//! A composition template can:
//!
//! 1. **Mix formats**: Nuclei HTTP check → YARA file scan → Sigma log check
//! 2. **Cross protocols**: HTTP probe → DNS check → TCP banner grab
//! 3. **Conditional flow**: if step 1 extracts version < 6.0, run CVE templates
//! 4. **User-defined chains**: any finding type can trigger any follow-up
//! 5. **Parallel steps**: run independent checks simultaneously
//!
//! # Example
//!
//! ```yaml
//! id: wordpress-full-audit
//! info:
//!   name: WordPress Full Audit
//!   severity: high
//!
//! compose:
//!   - step: detect
//!     http:
//!       path: "{{BaseURL}}"
//!       matchers:
//!         - type: word
//!           words: ["wp-content"]
//!       extractors:
//!         - type: regex
//!           name: version
//!           regex: ["content=\"WordPress ([\\d.]+)\""]
//!           group: 1
//!
//!   - step: check-version
//!     if: "version != ''"
//!     depends: [detect]
//!     http:
//!       path: "{{BaseURL}}/readme.html"
//!       matchers:
//!         - type: dsl
//!           dsl: ["compare_versions(version, '<', '6.0')"]
//!
//!   - step: scan-cves
//!     if: "check-version.matched"
//!     depends: [check-version]
//!     include:
//!       tags: [wordpress, cve]
//!       severity: [high, critical]
//!
//!   - step: yara-scan
//!     depends: [detect]
//!     yara:
//!       source: detect.response_body
//!       rules: ["wordpress-malware.yar"]
//!
//!   - step: dns-takeover
//!     parallel: true
//!     dns:
//!       type: CNAME
//!       name: "{{Host}}"
//!       matchers:
//!         - type: word
//!           words: ["amazonaws.com", "github.io", "herokuapp.com"]
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A composition template — the top-level structure for multi-step,
/// multi-format, multi-protocol vulnerability detection chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposeTemplate {
    /// Unique identifier.
    pub id: String,
    /// Human-readable metadata.
    pub info: ComposeInfo,
    /// Ordered list of composition steps.
    pub steps: Vec<ComposeStep>,
    /// Variables available to all steps.
    #[serde(default)]
    pub variables: HashMap<String, String>,
}

/// Metadata for a composition template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposeInfo {
    pub name: String,
    #[serde(default)]
    pub author: Vec<String>,
    #[serde(default)]
    pub severity: crate::Severity,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A single step in a composition chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposeStep {
    /// Step name — used for dependency references and result access.
    pub step: String,

    /// Condition for execution — DSL expression referencing previous step results.
    /// Example: "detect.matched && version != ''"
    #[serde(default)]
    #[serde(rename = "if")]
    pub condition: Option<String>,

    /// Steps that must complete before this one runs.
    #[serde(default)]
    pub depends: Vec<String>,

    /// Whether this step can run in parallel with other parallel steps.
    #[serde(default)]
    pub parallel: bool,

    /// The action to perform — exactly one of these should be set.
    #[serde(flatten)]
    pub action: StepAction,
}

/// The action a composition step performs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepAction {
    /// Execute an HTTP request (Nuclei-style).
    Http(HttpStepConfig),
    /// Execute a DNS query.
    Dns(DnsStepConfig),
    /// Execute a TCP connection and banner grab.
    Tcp(TcpStepConfig),
    /// Run YARA rules against data from a previous step.
    Yara(YaraStepConfig),
    /// Run Sigma rules against log data.
    Sigma(SigmaStepConfig),
    /// Include existing templates by tag/severity filter.
    Include(IncludeStepConfig),
    /// Run a custom chain rule triggered by previous findings.
    Chain(ChainStepConfig),
}

/// HTTP request step configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpStepConfig {
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub matchers: Vec<serde_json::Value>,
    #[serde(default)]
    pub extractors: Vec<serde_json::Value>,
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Option<String>,
}

/// DNS query step configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsStepConfig {
    #[serde(rename = "type")]
    pub query_type: String,
    pub name: String,
    #[serde(default)]
    pub matchers: Vec<serde_json::Value>,
}

/// TCP connection step configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpStepConfig {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub matchers: Vec<serde_json::Value>,
}

/// YARA rule step — run YARA against data from a previous step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStepConfig {
    /// Source of data to scan: `step_name.response_body` or a file path.
    pub source: String,
    /// YARA rule files or inline rules.
    pub rules: Vec<String>,
}

/// Sigma rule step — run Sigma detection against log data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaStepConfig {
    /// Source of log data.
    pub source: String,
    /// Sigma rule files.
    pub rules: Vec<String>,
}

/// Include existing templates by filter criteria.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncludeStepConfig {
    /// Include templates matching these tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Include templates at or above these severity levels.
    #[serde(default)]
    pub severity: Vec<String>,
    /// Include specific template IDs.
    #[serde(default)]
    pub ids: Vec<String>,
}

/// Custom chain rule — trigger follow-up based on previous findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStepConfig {
    /// Trigger condition: "finding.tag == 'sqli'" or "finding.kind == 'vulnerability'"
    pub trigger: String,
    /// What to do when triggered.
    pub action: ChainAction,
}

/// Action to take when a chain rule triggers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainAction {
    /// Verify the finding by resending with modification.
    Verify { modify: String },
    /// Extract data using a follow-up request.
    Extract { path: String, extractor: String },
    /// Run a specific template against the finding's URL.
    Template { id: String },
}

/// Result of executing a composition step.
#[derive(Debug, Clone, Default)]
pub struct StepResult {
    /// Whether the step's matchers were satisfied.
    pub matched: bool,
    /// Extracted variables from this step.
    pub extracted: HashMap<String, String>,
    /// Raw response body (for YARA/Sigma source references).
    pub response_body: Vec<u8>,
    /// Raw response headers.
    pub response_headers: Vec<u8>,
    /// HTTP status code (if applicable).
    pub status: u16,
    /// Findings produced by this step.
    pub findings: Vec<crate::Finding>,
}

/// Execution context for a composition template.
/// Tracks step results for dependency resolution and variable interpolation.
#[derive(Debug, Default)]
pub struct ComposeContext {
    /// Results indexed by step name.
    pub results: HashMap<String, StepResult>,
    /// Merged variables from all completed steps.
    pub variables: HashMap<String, String>,
}

impl ComposeContext {
    /// Check if a step's dependencies are all satisfied.
    pub fn dependencies_met(&self, step: &ComposeStep) -> bool {
        step.depends
            .iter()
            .all(|dep| self.results.contains_key(dep))
    }

    /// Evaluate a step's condition expression against the current context.
    pub fn condition_met(&self, step: &ComposeStep) -> bool {
        let Some(ref condition) = step.condition else {
            return true; // No condition = always run
        };

        // Simple condition evaluation
        let condition = condition.trim();

        // "step_name.matched" — check if a step produced matches
        if let Some(step_name) = condition.strip_suffix(".matched") {
            return self.results.get(step_name).is_some_and(|r| r.matched);
        }

        // "variable != ''" — check if a variable is non-empty
        if let Some((var, _)) = condition.split_once(" != ''") {
            let var = var.trim();
            return self.variables.get(var).is_some_and(|v| !v.is_empty());
        }

        // "variable == 'value'" — exact match
        if let Some((var, expected)) = condition.split_once(" == '") {
            let var = var.trim();
            let expected = expected.trim_end_matches('\'');
            return self.variables.get(var).is_some_and(|v| v == expected);
        }

        // Default: ignore unknown/unsupported conditions and fail securely 
        false
    }

    /// Register a step's result.
    pub fn complete_step(&mut self, step_name: &str, result: StepResult) {
        for (key, value) in &result.extracted {
            self.variables.insert(key.clone(), value.clone());
        }
        self.results.insert(step_name.to_string(), result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_context_dependencies_met() {
        let mut ctx = ComposeContext::default();
        ctx.complete_step(
            "detect",
            StepResult {
                matched: true,
                ..Default::default()
            },
        );

        let step = ComposeStep {
            step: "check".to_string(),
            condition: None,
            depends: vec!["detect".to_string()],
            parallel: false,
            action: StepAction::Http(HttpStepConfig {
                method: None,
                path: vec![],
                headers: HashMap::new(),
                body: None,
                matchers: vec![],
                extractors: vec![],
                matchers_condition: None,
            }),
        };

        assert!(ctx.dependencies_met(&step));
    }

    #[test]
    fn compose_context_condition_matched() {
        let mut ctx = ComposeContext::default();
        ctx.complete_step(
            "detect",
            StepResult {
                matched: true,
                ..Default::default()
            },
        );

        let step = ComposeStep {
            step: "followup".to_string(),
            condition: Some("detect.matched".to_string()),
            depends: vec!["detect".to_string()],
            parallel: false,
            action: StepAction::Http(HttpStepConfig {
                method: None,
                path: vec![],
                headers: HashMap::new(),
                body: None,
                matchers: vec![],
                extractors: vec![],
                matchers_condition: None,
            }),
        };

        assert!(ctx.condition_met(&step));
    }

    #[test]
    fn compose_context_variable_condition() {
        let mut ctx = ComposeContext::default();
        let mut extracted = HashMap::new();
        extracted.insert("version".to_string(), "5.9".to_string());
        ctx.complete_step(
            "detect",
            StepResult {
                matched: true,
                extracted,
                ..Default::default()
            },
        );

        let step_with_var = ComposeStep {
            step: "check".to_string(),
            condition: Some("version != ''".to_string()),
            depends: vec![],
            parallel: false,
            action: StepAction::Http(HttpStepConfig {
                method: None,
                path: vec![],
                headers: HashMap::new(),
                body: None,
                matchers: vec![],
                extractors: vec![],
                matchers_condition: None,
            }),
        };

        assert!(ctx.condition_met(&step_with_var));
    }

    #[test]
    fn compose_context_unmet_dependency() {
        let ctx = ComposeContext::default();

        let step = ComposeStep {
            step: "check".to_string(),
            condition: None,
            depends: vec!["missing_step".to_string()],
            parallel: false,
            action: StepAction::Http(HttpStepConfig {
                method: None,
                path: vec![],
                headers: HashMap::new(),
                body: None,
                matchers: vec![],
                extractors: vec![],
                matchers_condition: None,
            }),
        };

        assert!(!ctx.dependencies_met(&step));
    }

    #[test]
    fn compose_context_false_condition() {
        let mut ctx = ComposeContext::default();
        ctx.complete_step(
            "detect",
            StepResult {
                matched: false,
                ..Default::default()
            },
        );

        let step = ComposeStep {
            step: "followup".to_string(),
            condition: Some("detect.matched".to_string()),
            depends: vec![],
            parallel: false,
            action: StepAction::Http(HttpStepConfig {
                method: None,
                path: vec![],
                headers: HashMap::new(),
                body: None,
                matchers: vec![],
                extractors: vec![],
                matchers_condition: None,
            }),
        };

        assert!(!ctx.condition_met(&step));
    }

    #[test]
    fn deserialize_compose_template_json() {
        let json = r#"{
            "id": "test-compose",
            "info": {
                "name": "Test Composition",
                "severity": "high",
                "tags": ["test"]
            },
            "steps": [
                {
                    "step": "detect",
                    "http": {
                        "path": ["{{BaseURL}}"],
                        "matchers": [{"type": "word", "words": ["test"]}]
                    }
                },
                {
                    "step": "followup",
                    "if": "detect.matched",
                    "depends": ["detect"],
                    "dns": {
                        "type": "A",
                        "name": "{{Host}}",
                        "matchers": []
                    }
                }
            ]
        }"#;
        let template: ComposeTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(template.id, "test-compose");
        assert_eq!(template.steps.len(), 2);
        assert_eq!(template.steps[0].step, "detect");
        assert_eq!(template.steps[1].step, "followup");
        assert_eq!(
            template.steps[1].condition.as_deref(),
            Some("detect.matched")
        );
        assert_eq!(template.steps[1].depends, vec!["detect"]);
    }

    // ==================================================================
    // NEW TESTS - designed to expose gaps in composition handling
    // ==================================================================

    /// TEST 1: Circular step dependencies should be detected
    #[test]
    fn circular_step_dependencies() {
        let mut ctx = ComposeContext::default();

        // Step A depends on B, B depends on C, C depends on A (circular)
        let step_a = ComposeStep {
            step: "step_a".to_string(),
            condition: None,
            depends: vec!["step_c".to_string()], // depends on C
            parallel: false,
            action: StepAction::Http(HttpStepConfig::default()),
        };

        let step_b = ComposeStep {
            step: "step_b".to_string(),
            condition: None,
            depends: vec!["step_a".to_string()], // depends on A
            parallel: false,
            action: StepAction::Http(HttpStepConfig::default()),
        };

        let step_c = ComposeStep {
            step: "step_c".to_string(),
            condition: None,
            depends: vec!["step_b".to_string()], // depends on B - creates cycle
            parallel: false,
            action: StepAction::Http(HttpStepConfig::default()),
        };

        // Currently no circular dependency detection exists
        // This test documents the gap - ctx.dependencies_met will always return false for circular deps
        assert!(!ctx.dependencies_met(&step_a));
        assert!(!ctx.dependencies_met(&step_b));
        assert!(!ctx.dependencies_met(&step_c));

        // Complete step_a — step_b should now be runnable (it only depends on step_a)
        ctx.complete_step(
            "step_a",
            StepResult {
                matched: true,
                ..Default::default()
            },
        );
        assert!(ctx.dependencies_met(&step_b)); // step_b depends only on step_a
    }

    /// TEST 2: Step with nonexistent dependency should fail gracefully
    #[test]
    fn step_with_nonexistent_depends() {
        let ctx = ComposeContext::default();

        let step = ComposeStep {
            step: "orphan".to_string(),
            condition: None,
            depends: vec!["nonexistent_step".to_string()],
            parallel: false,
            action: StepAction::Http(HttpStepConfig::default()),
        };

        assert!(!ctx.dependencies_met(&step));
    }

    /// TEST 3: Empty compose list should be valid
    #[test]
    fn empty_compose_list() {
        let template = ComposeTemplate {
            id: "empty-compose".to_string(),
            info: ComposeInfo {
                name: "Empty".to_string(),
                author: vec![],
                severity: crate::Severity::Info,
                description: None,
                tags: vec![],
            },
            steps: vec![],
            variables: HashMap::new(),
        };

        assert!(template.steps.is_empty());

        let ctx = ComposeContext::default();
        // No steps to process - should be in terminal state
        assert!(ctx.results.is_empty());
    }

    /// TEST 4: Step with invalid if condition syntax
    #[test]
    fn step_with_invalid_if_condition() {
        let mut ctx = ComposeContext::default();
        ctx.complete_step(
            "detect",
            StepResult {
                matched: true,
                ..Default::default()
            },
        );

        let step = ComposeStep {
            step: "followup".to_string(),
            condition: Some("invalid syntax {{ here".to_string()),
            depends: vec![],
            parallel: false,
            action: StepAction::Http(HttpStepConfig::default()),
        };

        // Unrecognized conditions fail securely (return false)
        let result = ctx.condition_met(&step);
        assert!(!result, "invalid conditions should fail closed");
    }

    /// TEST 5: 50 steps deep nesting
    #[test]
    fn fifty_steps_deep_nesting() {
        let mut ctx = ComposeContext::default();

        // Create a chain of 50 dependent steps
        for i in 0..50 {
            let step = ComposeStep {
                step: format!("step_{}", i),
                condition: None,
                depends: if i == 0 {
                    vec![]
                } else {
                    vec![format!("step_{}", i - 1)]
                },
                parallel: false,
                action: StepAction::Http(HttpStepConfig::default()),
            };

            if i == 0 {
                assert!(ctx.dependencies_met(&step));
                ctx.complete_step(&format!("step_{}", i), StepResult::default());
            } else {
                // Each step depends on previous
                if ctx.dependencies_met(&step) {
                    ctx.complete_step(&format!("step_{}", i), StepResult::default());
                }
            }
        }

        // All 50 steps should be completed
        assert_eq!(ctx.results.len(), 50);
    }

    /// TEST 6: Parallel steps with conflicting variables
    #[test]
    fn parallel_steps_with_conflicting_variables() {
        let mut ctx = ComposeContext::default();

        // First parallel step extracts "version" = "1.0"
        let mut extracted1 = HashMap::new();
        extracted1.insert("version".to_string(), "1.0".to_string());
        ctx.complete_step(
            "parallel_a",
            StepResult {
                matched: true,
                extracted: extracted1,
                ..Default::default()
            },
        );

        // Second parallel step extracts "version" = "2.0"
        let mut extracted2 = HashMap::new();
        extracted2.insert("version".to_string(), "2.0".to_string());
        ctx.complete_step(
            "parallel_b",
            StepResult {
                matched: true,
                extracted: extracted2,
                ..Default::default()
            },
        );

        // Last write wins - version should be "2.0"
        assert_eq!(ctx.variables.get("version"), Some(&"2.0".to_string()));
    }

    /// TEST 7: Step that includes templates by tag that don't exist
    #[test]
    fn include_templates_by_nonexistent_tag() {
        let step = ComposeStep {
            step: "include_step".to_string(),
            condition: None,
            depends: vec![],
            parallel: false,
            action: StepAction::Include(IncludeStepConfig {
                tags: vec!["nonexistent-tag".to_string()],
                severity: vec![],
                ids: vec![],
            }),
        };

        // The include step is valid even if no templates match
        assert!(matches!(step.action, StepAction::Include(_)));
    }

    /// TEST 8: Version comparison in if condition
    #[test]
    fn version_comparison_in_if_condition() {
        let mut ctx = ComposeContext::default();

        // Extract a version number
        let mut extracted = HashMap::new();
        extracted.insert("version".to_string(), "5.9".to_string());
        ctx.complete_step(
            "detect",
            StepResult {
                matched: true,
                extracted,
                ..Default::default()
            },
        );

        // Current implementation doesn't support version comparison operators
        // This test documents the gap
        let step = ComposeStep {
            step: "check_version".to_string(),
            condition: Some("version < '6.0'".to_string()), // Not supported
            depends: vec![],
            parallel: false,
            action: StepAction::Http(HttpStepConfig::default()),
        };

        // Version comparison operators not yet supported — fails closed
        let result = ctx.condition_met(&step);
        assert!(!result, "unsupported operators should fail closed");
    }

    /// TEST 9: Step output passed to next step
    #[test]
    fn step_output_passed_to_next_step() {
        let mut ctx = ComposeContext::default();

        // First step produces output
        ctx.complete_step(
            "extract",
            StepResult {
                matched: true,
                extracted: [("token".to_string(), "secret123".to_string())]
                    .into_iter()
                    .collect(),
                response_body: b"body content".to_vec(),
                response_headers: b"X-Header: value".to_vec(),
                status: 200,
                ..Default::default()
            },
        );

        // Verify the result is accessible
        let result = ctx
            .results
            .get("extract")
            .expect("Step result should exist");
        assert!(result.matched);
        assert_eq!(
            result.extracted.get("token"),
            Some(&"secret123".to_string())
        );
        assert_eq!(result.response_body, b"body content");

        // Check dependency resolution works
        let next_step = ComposeStep {
            step: "use_token".to_string(),
            condition: Some("extract.matched".to_string()),
            depends: vec!["extract".to_string()],
            parallel: false,
            action: StepAction::Http(HttpStepConfig::default()),
        };

        assert!(ctx.dependencies_met(&next_step));
        assert!(ctx.condition_met(&next_step));
    }

    /// TEST 10: Compose template with no matchers
    #[test]
    fn compose_template_with_no_matchers() {
        let template = ComposeTemplate {
            id: "no-matchers".to_string(),
            info: ComposeInfo {
                name: "No Matchers".to_string(),
                author: vec![],
                severity: crate::Severity::Info,
                description: None,
                tags: vec![],
            },
            steps: vec![ComposeStep {
                step: "probe".to_string(),
                condition: None,
                depends: vec![],
                parallel: false,
                action: StepAction::Http(HttpStepConfig {
                    method: Some("GET".to_string()),
                    path: vec!["/".to_string()],
                    headers: HashMap::new(),
                    body: None,
                    matchers: vec![], // No matchers
                    extractors: vec![],
                    matchers_condition: None,
                }),
            }],
            variables: HashMap::new(),
        };

        // Template with no matchers is valid - just does a request
        match &template.steps[0].action {
            StepAction::Http(config) => {
                assert!(config.matchers.is_empty());
            }
            _ => panic!("Expected HTTP action"),
        }
    }
}
