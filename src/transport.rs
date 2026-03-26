//! Transport planning and execution traits shared between planners and clients.

use crate::matcher::ResponseData;
use crate::{Result, Template};
use std::collections::HashMap;

/// A target URL to scan.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetUrl(pub String);

impl TargetUrl {
    /// Create a target URL wrapper from any string-like input.
    pub fn new(url: impl Into<String>) -> Self {
        Self(url.into())
    }

    /// Borrow the target URL as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TargetUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A planned HTTP request, deduplicated across templates.
///
/// If 200 templates all need `GET /`, the planner emits one `RequestSpec`
/// tagged with all 200 template IDs. The transport sends it once.
/// The engine matches the single response against all 200 templates.
#[derive(Debug, Clone, Default)]
pub struct RequestSpec {
    /// Original scan target this request belongs to.
    pub target: String,

    /// Target URL with path applied.
    pub url: String,

    /// HTTP method.
    pub method: String,

    /// Headers to send.
    pub headers: HashMap<String, String>,

    /// Request body.
    pub body: Option<Vec<u8>>,

    /// Which templates expect this request.
    /// Maps `template_id` -> `request_index` within that template.
    pub template_refs: Vec<(String, usize)>,

    /// Follow redirects.
    pub follow_redirects: bool,

    /// Max redirects.
    pub max_redirects: u32,

    /// Reuse cookies across requests in the same template sequence.
    pub cookie_reuse: bool,
}

/// Runtime variables available for a specific target/template execution.
#[derive(Debug, Clone, Default)]
pub struct TemplateContext {
    /// Original target URL for this execution.
    pub target: String,

    /// Template identifier.
    pub template_id: String,

    /// Extracted and template-defined variables available for substitution.
    pub variables: HashMap<String, String>,
}

/// The full execution plan: all requests needed, deduplicated.
#[derive(Debug, Clone, Default)]
pub struct RequestPlan {
    /// Deduplicated requests to execute.
    pub requests: Vec<RequestSpec>,

    /// Total unique target URLs.
    pub target_count: usize,

    /// Total templates being evaluated.
    pub template_count: usize,

    /// How many raw requests were deduplicated away.
    pub dedup_savings: usize,
}

/// An HTTP response paired with the spec that produced it.
#[derive(Debug)]
pub struct Response {
    /// The request spec that produced this response.
    pub spec: RequestSpec,

    /// Parsed response data ready for matching.
    pub data: ResponseData,

    /// Wall-clock time for the request.
    pub elapsed: std::time::Duration,
}

/// Sends HTTP requests and returns responses.
///
/// Implementations may use reqwest, hyper, `io_uring`, or any HTTP client.
/// The trait abstracts the transport layer so the engine doesn't care.
pub trait Transport: Send + Sync {
    /// Returns the transport's effective concurrency limit.
    fn concurrency_limit(&self) -> usize {
        1
    }

    /// Execute a batch of requests and return responses.
    ///
    /// The transport should respect concurrency limits internally.
    /// Responses are returned as they complete (not necessarily in order).
    fn execute(
        &self,
        plan: &RequestPlan,
    ) -> std::pin::Pin<Box<dyn futures::Stream<Item = Result<Response>> + Send + '_>>;
}

/// Deduplicates requests across templates.
///
/// The planner examines all templates and all targets, identifies
/// identical HTTP requests needed by multiple templates, and collapses
/// them into single `RequestSpec`s tagged with all interested template IDs.
pub trait Planner: Send + Sync {
    /// Generate a deduplicated request plan from targets and templates.
    fn plan(&self, targets: &[TargetUrl], templates: &[Template]) -> RequestPlan;

    /// Generate a deduplicated plan for a single request index across active contexts.
    fn plan_step(
        &self,
        targets: &[TargetUrl],
        templates: &[Template],
        request_index: usize,
        contexts: &[TemplateContext],
    ) -> RequestPlan;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_url_display() {
        let target = TargetUrl::new("https://example.com");
        assert_eq!(target.to_string(), "https://example.com");
        assert_eq!(target.as_str(), "https://example.com");
    }

    #[test]
    fn request_plan_dedup_savings() {
        let plan = RequestPlan {
            requests: vec![],
            target_count: 10,
            template_count: 200,
            dedup_savings: 1800,
        };
        assert_eq!(plan.dedup_savings, 1800);
    }
}
