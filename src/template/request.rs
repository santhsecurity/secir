use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::matchers::{
    default_matcher_condition, ExtractorDef, MatchConfig, MatcherCondition, MatcherDef,
};

/// Protocol-specific request type for the v2 template IR.
///
/// Each variant carries only the fields relevant to that protocol,
/// eliminating the 20-field `RequestDef` for non-HTTP protocols.
/// The `Custom` variant allows plugins to define their own request types.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ProtocolRequest {
    Http(HttpRequestDef),
    Dns(DnsRequestDef),
    Tcp(TcpRequestDef),
    Ssl(SslRequestDef),
    Websocket(WebsocketRequestDef),
    Code(CodeRequestDef),
    File(FileRequestDef),
    Whois(WhoisRequestDef),
    Headless(HeadlessRequestDef),
    Custom {
        #[serde(rename = "custom_protocol")]
        protocol_name: String,
        data: serde_json::Value,
    },
}

/// A single HTTP request definition within a template.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpRequestConfig {
    #[serde(default = "default_method")]
    pub method: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default = "default_true")]
    pub redirects: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PayloadConfig {
    #[serde(default)]
    pub payloads: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub attack: AttackType,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpRequestDef {
    #[serde(flatten)]
    pub request: HttpRequestConfig,
    #[serde(flatten)]
    pub matching: MatchConfig,
    #[serde(flatten)]
    pub payloads: PayloadConfig,

    #[serde(default)]
    pub call: Option<String>,
    #[serde(default)]
    pub raw: Option<Vec<String>>,
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub inputs: Vec<NetworkInput>,
    #[serde(default = "default_max_redirects")]
    pub max_redirects: u32,
    #[serde(default)]
    pub stop_at_first_match: bool,
    #[serde(default)]
    pub encoding: Option<Vec<Encoding>>,
    #[serde(default)]
    pub differential: bool,
    #[serde(default)]
    pub max_response_time_ms: Option<u64>,
    #[serde(default = "default_true", rename = "cookie-reuse")]
    pub cookie_reuse: bool,
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default)]
    pub iterate: Option<IterateConfig>,
    #[serde(default)]
    pub transforms: Option<Vec<Transform>>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RequestDef {
    /// Call an imported template instead of making an HTTP request.
    #[serde(default)]
    pub call: Option<String>,

    /// HTTP method.
    #[serde(default = "default_method")]
    pub method: String,

    /// Original raw HTTP request blocks, when the template used `raw`.
    #[serde(default)]
    pub raw: Option<Vec<String>>,

    /// Path(s) to request. Multiple paths = multiple requests from this def.
    pub paths: Vec<String>,

    /// Headers to include.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Request body (for POST, PUT, etc.)
    #[serde(default)]
    pub body: Option<String>,

    /// Explicit port for non-HTTP protocols such as TCP.
    #[serde(default)]
    pub port: Option<String>,

    /// Ordered socket I/O steps for network templates.
    #[serde(default)]
    pub inputs: Vec<NetworkInput>,

    /// Payload dictionaries for fuzzing-style request expansion.
    #[serde(default)]
    pub payloads: HashMap<String, Vec<String>>,

    /// Strategy used to combine multiple payload dictionaries.
    #[serde(default)]
    pub attack: AttackType,

    /// Matchers that must pass for this request to produce a finding.
    pub matchers: Vec<MatcherDef>,

    /// How multiple matchers combine: "and" (all must match) or "or" (any).
    #[serde(default = "default_matcher_condition")]
    pub matchers_condition: MatcherCondition,

    /// Extractors pull data from responses for use in subsequent requests.
    #[serde(default)]
    pub extractors: Vec<ExtractorDef>,

    /// Follow redirects.
    #[serde(default = "default_true")]
    pub redirects: bool,

    /// Maximum redirects to follow.
    #[serde(default = "default_max_redirects")]
    pub max_redirects: u32,

    /// Stop scanning this template after the first match.
    /// Nuclei calls this "stop-at-first-match". Massive speedup for large scans.
    #[serde(default)]
    pub stop_at_first_match: bool,

    /// Automatic encoding variants to generate for this request.
    #[serde(default)]
    pub encoding: Option<Vec<Encoding>>,

    /// Enable differential scanning for this request.
    #[serde(default)]
    pub differential: bool,

    /// Flag if response takes longer than this threshold.
    #[serde(default)]
    pub max_response_time_ms: Option<u64>,

    /// Reuse cookies set by earlier requests in this template sequence.
    #[serde(default = "default_true", rename = "cookie-reuse")]
    pub cookie_reuse: bool,

    /// DSL expression, skip request if false
    #[serde(default)]
    pub condition: Option<String>,

    /// loop over extracted list
    #[serde(default)]
    pub iterate: Option<IterateConfig>,

    /// response transforms before matching
    #[serde(default)]
    pub transforms: Vec<Transform>,

    /// jump target for goto
    #[serde(default)]
    pub label: Option<String>,

    /// jump to labeled request on match
    #[serde(default)]
    pub goto: Option<String>,

    /// raw headless actions
    #[serde(default)]
    pub headless_actions: Vec<serde_json::Value>,
}

impl RequestDef {
    /// Returns the request method.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the configured request paths.
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// Returns the request matchers.
    pub fn matchers(&self) -> &[MatcherDef] {
        &self.matchers
    }

    /// Returns the request extractors.
    pub fn extractors(&self) -> &[ExtractorDef] {
        &self.extractors
    }
}

/// A DNS request definition within a template.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsRequestDef {
    #[serde(default)]
    pub call: Option<String>,
    pub name: String,
    #[serde(default = "default_dns_query_type")]
    pub query_type: String,
    #[serde(default)]
    pub query_class: Option<String>,
    #[serde(default = "default_true")]
    pub recursion: bool,
    #[serde(default)]
    pub matchers: Vec<MatcherDef>,
    #[serde(default = "default_matcher_condition")]
    pub matchers_condition: MatcherCondition,
    #[serde(default)]
    pub extractors: Vec<ExtractorDef>,
    #[serde(default)]
    pub stop_at_first_match: bool,
}

/// A raw TCP request definition within a template.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TcpRequestDef {
    #[serde(default)]
    pub call: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub inputs: Vec<NetworkInput>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub read_size: Option<usize>,
    #[serde(default)]
    pub matchers: Vec<MatcherDef>,
    #[serde(default = "default_matcher_condition")]
    pub matchers_condition: MatcherCondition,
    #[serde(default)]
    pub extractors: Vec<ExtractorDef>,
    #[serde(default)]
    pub stop_at_first_match: bool,
}

/// An SSL/TLS metadata request definition within a template.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SslRequestDef {
    #[serde(default)]
    pub call: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub matchers: Vec<MatcherDef>,
    #[serde(default = "default_matcher_condition")]
    pub matchers_condition: MatcherCondition,
    #[serde(default)]
    pub stop_at_first_match: bool,
}

/// A WebSocket request definition within a template.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebsocketRequestDef {
    #[serde(default)]
    pub call: Option<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub inputs: Vec<NetworkInput>,
    #[serde(default)]
    pub matchers: Vec<MatcherDef>,
    #[serde(default = "default_matcher_condition")]
    pub matchers_condition: MatcherCondition,
    #[serde(default)]
    pub extractors: Vec<ExtractorDef>,
    #[serde(default)]
    pub stop_at_first_match: bool,
}

/// An embedded code execution request definition within a template.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodeRequestDef {
    #[serde(default)]
    pub call: Option<String>,
    #[serde(default)]
    pub engine: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub matchers: Vec<MatcherDef>,
    #[serde(default = "default_matcher_condition")]
    pub matchers_condition: MatcherCondition,
    #[serde(default)]
    pub extractors: Vec<ExtractorDef>,
    #[serde(default)]
    pub stop_at_first_match: bool,
}

/// A file system scanning request definition within a template.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileRequestDef {
    #[serde(default)]
    pub call: Option<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub matchers: Vec<MatcherDef>,
    #[serde(default = "default_matcher_condition")]
    pub matchers_condition: MatcherCondition,
    #[serde(default)]
    pub extractors: Vec<ExtractorDef>,
    #[serde(default)]
    pub stop_at_first_match: bool,
}

/// A WHOIS request definition within a template.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhoisRequestDef {
    #[serde(default)]
    pub call: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub matchers: Vec<MatcherDef>,
    #[serde(default = "default_matcher_condition")]
    pub matchers_condition: MatcherCondition,
    #[serde(default)]
    pub extractors: Vec<ExtractorDef>,
    #[serde(default)]
    pub stop_at_first_match: bool,
}

/// A browser automation request definition within a template.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeadlessRequestDef {
    #[serde(default)]
    pub call: Option<String>,
    #[serde(default)]
    pub start_urls: Vec<String>,
    #[serde(default)]
    pub actions: Vec<serde_json::Value>,
    #[serde(default)]
    pub matchers: Vec<MatcherDef>,
    #[serde(default = "default_matcher_condition")]
    pub matchers_condition: MatcherCondition,
    #[serde(default)]
    pub extractors: Vec<ExtractorDef>,
    #[serde(default)]
    pub stop_at_first_match: bool,
}

/// A single input/read step for TCP-style network templates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInput {
    /// Raw template data to send to the socket.
    #[serde(default)]
    pub data: Option<String>,

    /// Encoding for `data`.
    #[serde(default)]
    pub data_type: NetworkInputType,

    /// Number of bytes to read after this step.
    #[serde(default)]
    pub read_size: usize,

    /// Optional name for this read buffer, addressable via matcher `part`.
    #[serde(default)]
    pub name: Option<String>,
}

/// Encoding used by a network input step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NetworkInputType {
    /// Treat `data` as a plain string.
    #[default]
    String,
    /// Treat `data` as hex-encoded bytes.
    Hex,
}

/// Strategy used to combine payload sets while expanding requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum AttackType {
    /// Reuse the same payload value across all positions.
    #[default]
    BatteringRam,
    /// Advance each payload list in lockstep.
    PitchFork,
    /// Try every combination across payload lists.
    ClusterBomb,
}

/// Payload encoding strategy used for automatic WAF-evasion variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Encoding {
    #[serde(rename = "url", alias = "urlencode")]
    UrlEncode,
    #[serde(rename = "double-url", alias = "doubleurlencode")]
    DoubleUrlEncode,
    #[serde(rename = "html", alias = "htmlencode")]
    HtmlEncode,
    #[serde(rename = "unicode", alias = "unicodeencode")]
    UnicodeEncode,
    #[serde(rename = "base64", alias = "base64encode")]
    Base64Encode,
    #[serde(rename = "hex", alias = "hexencode")]
    HexEncode,
}

impl RequestDef {
    /// Create a new request definition with default values.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a GET request definition with the given paths.
    pub fn http_get(paths: Vec<String>) -> Self {
        Self {
            method: "GET".to_string(),
            paths,
            ..Default::default()
        }
    }

    /// Create a POST request definition with the given paths and body.
    pub fn http_post(paths: Vec<String>, body: String) -> Self {
        Self {
            method: "POST".to_string(),
            paths,
            body: Some(body),
            ..Default::default()
        }
    }

    /// Set the HTTP method.
    #[inline]
    #[must_use]
    pub fn builder_method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }
}

/// Configuration for iterating over extracted lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterateConfig {
    /// The list variable to iterate over.
    pub over: String,
    /// The variable name to bind each item to.
    pub as_var: String,
    /// Maximum number of iterations.
    #[serde(default)]
    pub max: Option<usize>,
}

/// Data transformations applied before matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Transform {
    /// Base64 decode.
    Base64Decode,
    /// JWT decode.
    JwtDecode,
    /// JSON parse extraction.
    JsonParse {
        /// JSON path to extract.
        path: String,
    },
    /// Gzip decompress.
    GzipDecompress,
    /// Hex decode.
    HexDecode,
    /// URL decode.
    UrlDecode,
}

pub(crate) fn default_method() -> String {
    "GET".to_string()
}

pub(crate) fn default_dns_query_type() -> String {
    "A".to_string()
}

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_max_redirects() -> u32 {
    10
}
