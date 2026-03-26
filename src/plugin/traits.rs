
use crate::{Finding, Result, Template};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata describing a completed scan for reporter plugins.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanMetadata {
    /// Optional scan identifier for correlating reports.
    #[serde(default)]
    pub scan_id: Option<String>,
    /// When the scan started.
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    /// When the scan completed.
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
    /// Number of targets scanned.
    #[serde(default)]
    pub targets_scanned: usize,
    /// Number of templates evaluated.
    #[serde(default)]
    pub templates_evaluated: usize,
    /// Number of requests actually sent.
    #[serde(default)]
    pub requests_sent: usize,
    /// Number of requests removed by deduplication.
    #[serde(default)]
    pub requests_deduped: usize,
    /// Additional plugin- or runtime-specific metadata.
    #[serde(default)]
    pub extensions: HashMap<String, serde_json::Value>,
}

/// Universal extension point for Karyx capabilities.
pub trait Plugin: Send + Sync {
    /// Returns the stable plugin identifier.
    fn id(&self) -> &str;
    /// Returns the human-readable plugin name.
    fn name(&self) -> &str;
    /// Returns the plugin version string.
    fn version(&self) -> &str;
    /// Returns the capabilities exported by this plugin instance.
    fn capabilities(&self) -> smallvec::SmallVec<[PluginCapability; 4]>;
}

/// Protocol-specific scanners provided by plugins.
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// Executes a protocol-specific scan against one target using one compiled template.
    ///
    /// Lifecycle:
    /// - The runtime calls `scan()` after template loading/compilation and target
    ///   expansion are already complete.
    /// - Each call is independent. Handlers should treat the `target` + `template`
    ///   pair as a self-contained unit of work.
    /// - The runtime may call `scan()` many times over the lifetime of one handler
    ///   instance, so constructor state should be reusable and cheap to clone/share.
    ///
    /// Concurrency expectations:
    /// - `ProtocolHandler` is `Send + Sync`, so implementations must be safe to call
    ///   from multiple tasks at the same time.
    /// - Do not assume one in-flight scan at a time. If the handler keeps pools,
    ///   caches, or auth state, guard them with the usual async synchronization tools.
    /// - Keep per-scan mutable state local to `scan()` unless it is intentionally shared.
    ///
    /// Error handling guidance:
    /// - Return an empty `Vec` when the target is unreachable, the protocol handshake
    ///   fails, the template is invalid for this protocol, or response parsing fails.
    /// - Log or trace internal errors when useful, but do not panic for target-specific
    ///   failures. A bad host or malformed response should not abort the overall scan.
    /// - Never use panics for control flow. Protocol handlers are expected to fail closed.
    ///
    /// Example: a minimal MQTT-style handler
    /// ```ignore
    /// use karyx_core::plugin::ProtocolHandler;
    /// use karyx_core::template::{MatchPart, RequestDef, Template};
    /// use karyx_core::Finding;
    /// use karyx_protocol_common::matching::{
    ///     ProtocolResponse, collect_matched_values, request_matches,
    /// };
    /// use std::future::Future;
    /// use std::pin::Pin;
    ///
    /// struct ExampleMqttHandler;
    ///
    /// impl ProtocolHandler for ExampleMqttHandler {
    ///     fn scan<'life0, 'life1, 'async_trait>(
    ///         &'life0 self,
    ///         target: &'life1 str,
    ///         template: &'life1 Template,
    ///     ) -> Pin<Box<dyn Future<Output = Vec<Finding>> + Send + 'async_trait>>
    ///     where
    ///         'life0: 'async_trait,
    ///         'life1: 'async_trait,
    ///         Self: 'async_trait,
    ///     {
    ///         Box::pin(async move {
    ///             if !target.starts_with("mqtt://") {
    ///                 return Vec::new();
    ///             }
    ///
    ///             let mut findings = Vec::new();
    ///             for request in &template.requests {
    ///                 let topics = topics_from_request(request);
    ///                 if topics.is_empty() {
    ///                     continue;
    ///                 }
    ///
    ///                 let responses = vec![MqttResponse::new(
    ///                     "sensors/office",
    ///                     "temperature=21",
    ///                 )];
    ///
    ///                 for response in responses {
    ///                     if !request_matches(request, &response) {
    ///                         continue;
    ///                     }
    ///
    ///                     let matched_values = collect_matched_values(request, &response);
    ///                     findings.push(Finding::from_template(
    ///                         template,
    ///                         target.to_string(),
    ///                         format!("mqtt://broker/{}", response.topic),
    ///                         matched_values,
    ///                     ));
    ///
    ///                     if request.stop_at_first_match {
    ///                         return findings;
    ///                     }
    ///                 }
    ///             }
    ///
    ///             findings
    ///         })
    ///     }
    ///
    ///     fn protocol_name(&self) -> &str {
    ///         "mqtt"
    ///     }
    /// }
    ///
    /// struct MqttResponse {
    ///     topic: String,
    ///     payload: String,
    ///     all: String,
    /// }
    ///
    /// impl MqttResponse {
    ///     fn new(topic: &str, payload: &str) -> Self {
    ///         Self {
    ///             topic: topic.to_string(),
    ///             payload: payload.to_string(),
    ///             all: format!("topic: {topic}\n\n{payload}"),
    ///         }
    ///     }
    /// }
    ///
    /// impl ProtocolResponse for MqttResponse {
    ///     fn text_for_part(&self, part: &MatchPart) -> &str {
    ///         match part {
    ///             MatchPart::Body => &self.payload,
    ///             MatchPart::Header => &self.topic,
    ///             MatchPart::All => &self.all,
    ///             MatchPart::Named(name) if name.eq_ignore_ascii_case("topic") => &self.topic,
    ///             MatchPart::Named(_) => &self.payload,
    ///         }
    ///     }
    /// }
    ///
    /// fn topics_from_request(request: &RequestDef) -> Vec<String> {
    ///     request
    ///         .paths
    ///         .iter()
    ///         .map(|topic| topic.trim())
    ///         .filter(|topic| !topic.is_empty())
    ///         .map(ToOwned::to_owned)
    ///         .collect()
    /// }
    /// ```
    async fn scan(&self, target: &str, template: &Template) -> Vec<Finding>;
    /// Returns the protocol name handled by this scanner.
    fn protocol_name(&self) -> &str;
}

/// Template compilers that translate source files into Karyx IR templates.
pub trait TemplateCompiler: Send + Sync {
    /// Returns the compiler name.
    fn name(&self) -> &str;
    /// Returns the file extensions this compiler accepts.
    fn file_extensions(&self) -> &[&str];
    /// Compiles source bytes into one or more Karyx templates.
    ///
    /// # Errors
    ///
    /// Returns an error when the source cannot be parsed or validated as a template.
    fn compile(&self, source: &[u8], path: &str) -> Result<Vec<Template>>;
}

/// Custom matching logic beyond the built-in matcher kinds.
pub trait CustomMatcher: Send + Sync {
    /// Returns the matcher name used for registration and lookup.
    fn name(&self) -> &str;
    /// Evaluates whether the provided data satisfies the matcher.
    fn matches(&self, data: &[u8], values: &[String], negative: bool) -> bool;
    /// Returns the concrete values that matched in the provided data.
    fn matched_values(&self, data: &[u8], values: &[String]) -> Vec<String>;
}

/// Custom extraction logic beyond the built-in extractor kinds.
pub trait CustomExtractor: Send + Sync {
    /// Returns the extractor name used for registration and lookup.
    fn name(&self) -> &str;
    /// Extracts a value from the provided data using the configured patterns and group.
    fn extract(&self, data: &[u8], patterns: &[String], group: usize) -> Option<String>;
}

/// Custom data transforms beyond the built-in transform pipeline.
pub trait CustomTransform: Send + Sync {
    /// Returns the transform name used for registration and lookup.
    fn name(&self) -> &str;
    /// Transforms raw data before matching or further processing.
    fn transform(&self, data: &[u8]) -> Vec<u8>;
}

/// Report generation plugins for alternate output formats and sinks.
#[async_trait]
pub trait CustomReporter: Send + Sync {
    /// Returns the reporter name.
    fn name(&self) -> &str;
    /// Returns the output format key handled by this reporter.
    fn format(&self) -> &str;
    /// Produces a serialized report for the provided findings and scan metadata.
    async fn report(&self, findings: &[Finding], metadata: &ScanMetadata) -> Result<Vec<u8>>;
}

/// Post-processing hooks that enrich or mutate findings after a scan completes.
#[async_trait]
pub trait PostProcessor: Send + Sync {
    /// Returns the post-processor name.
    fn name(&self) -> &str;
    /// Mutates or enriches findings after a scan completes.
    async fn process(&self, findings: &mut Vec<Finding>);
}

// ── Future-proof extension traits ──────────────────────────────────────────
// These traits define every swappable capability boundary in the runtime.
// Adding a new security paradigm = implementing a trait, never modifying core.

/// Discovers targets to scan from external sources (asset inventories, DNS, CIDR, etc.)
#[async_trait]
pub trait TargetDiscovery: Send + Sync {
    /// Returns the discovery backend name.
    fn name(&self) -> &str;
    /// Expands a seed input into scan targets.
    async fn discover(&self, seed: &str) -> Result<Vec<String>>;
}

/// Authenticates against a target before scanning (login flows, OAuth, API keys, etc.)
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Returns the authenticator name.
    fn name(&self) -> &str;
    /// Returns headers/cookies to inject into all subsequent requests for this target.
    async fn authenticate(
        &self,
        target: &str,
        config: &std::collections::HashMap<String, String>,
    ) -> Result<std::collections::HashMap<String, String>>;
}

/// Persists and queries findings across scan runs (dedup, trending, regression).
#[async_trait]
pub trait FindingStore: Send + Sync {
    /// Returns the store name.
    fn name(&self) -> &str;
    /// Persists the provided findings.
    async fn store(&self, findings: &[Finding]) -> Result<()>;
    /// Returns whether the finding is already known to the store.
    async fn is_known(&self, finding: &Finding) -> Result<bool>;
    /// Queries persisted findings using a backend-specific filter.
    async fn query(
        &self,
        filter: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<Finding>>;
}

/// Controls request rate per host, per scan, or globally.
pub trait RateLimiter: Send + Sync {
    /// Returns the rate limiter name.
    fn name(&self) -> &str;
    /// Returns the delay duration if the request should be throttled.
    fn should_throttle(&self, host: &str) -> Option<std::time::Duration>;
    /// Records a response for adaptive rate adjustment.
    fn record_response(&self, host: &str, status: u16, elapsed: std::time::Duration);
}

/// Resolves DNS queries (custom resolvers, `DoH`, internal DNS, etc.)
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Returns the resolver name.
    fn name(&self) -> &str;
    /// Resolves a hostname into IP addresses.
    async fn resolve(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>>;
}

/// Schedules and triggers recurring scans.
#[async_trait]
pub trait ScanScheduler: Send + Sync {
    /// Returns the scheduler name.
    fn name(&self) -> &str;
    /// Returns the next scan job to run, if one is scheduled.
    async fn next_scan(&self) -> Result<Option<ScanJob>>;
    /// Marks a scheduled job as complete with the resulting findings.
    async fn complete(&self, job: &ScanJob, findings: &[Finding]) -> Result<()>;
}

/// A scheduled scan job.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanJob {
    /// Unique job identifier.
    pub id: String,
    /// Targets to scan.
    pub targets: Vec<String>,
    /// Template filter tags.
    pub tags: Vec<String>,
    /// When this job was scheduled.
    pub scheduled_at: chrono::DateTime<chrono::Utc>,
}

/// The capabilities a plugin can contribute to the runtime.
pub enum PluginCapability {
    /// Provides a protocol handler.
    Protocol {
        /// Name of the protocol.
        name: String,
        /// The protocol handler implementation.
        handler: Box<dyn ProtocolHandler>,
    },
    /// Provides a template compiler.
    Compiler {
        /// Name of the compiler.
        name: String,
        /// The compiler implementation.
        handler: Box<dyn TemplateCompiler>,
    },
    /// Provides a custom matcher.
    Matcher {
        /// Name of the matcher.
        name: String,
        /// The matcher implementation.
        handler: Box<dyn CustomMatcher>,
    },
    /// Provides a custom extractor.
    Extractor {
        /// Name of the extractor.
        name: String,
        /// The extractor implementation.
        handler: Box<dyn CustomExtractor>,
    },
    /// Provides a custom transform.
    Transform {
        /// Name of the transform.
        name: String,
        /// The transform implementation.
        handler: Box<dyn CustomTransform>,
    },
    /// Provides a custom reporter.
    Reporter {
        /// Name of the reporter.
        name: String,
        /// The reporter implementation.
        handler: Box<dyn CustomReporter>,
    },
    /// Provides a post-processor.
    PostProcessor {
        /// Name of the post-processor.
        name: String,
        /// The post-processor implementation.
        handler: Box<dyn PostProcessor>,
    },
    /// Provides a target discovery source.
    Discovery {
        name: String,
        handler: Box<dyn TargetDiscovery>,
    },
    /// Provides an authentication handler.
    Auth {
        name: String,
        handler: Box<dyn Authenticator>,
    },
    /// Provides a finding persistence store.
    Store {
        name: String,
        handler: Box<dyn FindingStore>,
    },
    /// Provides a rate limiter.
    RateLimit {
        name: String,
        handler: Box<dyn RateLimiter>,
    },
    /// Provides a DNS resolver.
    Dns {
        name: String,
        handler: Box<dyn DnsResolver>,
    },
    /// Provides a scan scheduler.
    Scheduler {
        name: String,
        handler: Box<dyn ScanScheduler>,
    },
}
