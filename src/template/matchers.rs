use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MatchConfig {
    #[serde(default)]
    pub matchers: Vec<MatcherDef>,
    #[serde(default = "default_matcher_condition")]
    pub matchers_condition: MatcherCondition,
    #[serde(default)]
    pub extractors: Vec<ExtractorDef>,
}

/// How multiple matchers combine within a single request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum MatcherCondition {
    /// Every matcher or matcher value must succeed.
    And,
    /// Any matcher or matcher value may succeed.
    #[default]
    Or,
}

/// A single matcher — tests whether a response matches a pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatcherDef {
    /// What kind of matching to perform.
    #[serde(rename = "type")]
    pub kind: MatcherKind,

    /// The patterns/values to match against.
    /// Interpretation depends on `kind`:
    /// - Word/Regex: list of patterns
    /// - Status: list of status codes as strings
    /// - Size: list of expected content lengths as strings
    #[serde(default)]
    pub values: Vec<String>,

    /// Which part of the response to match against.
    #[serde(default = "default_part")]
    pub part: MatchPart,

    /// If true, this matcher must NOT match for the request to succeed.
    #[serde(default)]
    pub negative: bool,

    /// For multiple values: "and" = all must match, "or" = any.
    #[serde(default = "default_matcher_condition")]
    pub condition: MatcherCondition,

    /// Whether this matcher is used only for internal flow control.
    #[serde(default)]
    pub internal: bool,
}

/// The type of matching to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum MatcherKind {
    /// Case-insensitive substring match (fast path — Aho-Corasick).
    Word,
    /// Regular expression match.
    Regex,
    /// HTTP status code match.
    Status,
    /// Response body size match.
    Size,
    /// Binary content match (hex encoded).
    Binary,
    /// DSL expression (Nuclei's expression language).
    Dsl,
}

/// Which part of the HTTP response to match against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum MatchPart {
    /// Match against the response body bytes.
    Body,
    /// Match against serialized response headers.
    Header,
    /// Match against the combined headers and body buffer.
    All,
    /// Match against a specific header by name.
    #[serde(untagged)]
    Named(String),
}

/// Extracts data from a response for use in subsequent requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractorDef {
    /// Extractor type.
    #[serde(rename = "type")]
    pub kind: ExtractorKind,

    /// Patterns to extract.
    #[serde(default)]
    pub patterns: Vec<String>,

    /// Name to bind the extracted value to.
    pub name: Option<String>,

    /// Which part of the response to extract from.
    #[serde(default = "default_part")]
    pub part: MatchPart,

    /// Regex group to extract (0 = full match).
    #[serde(default)]
    pub group: usize,

    /// Whether this extractor's output is used internally only
    /// (not displayed in findings).
    #[serde(default)]
    pub internal: bool,
}

/// Extractor type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ExtractorKind {
    /// Regular expression extraction.
    Regex,
    /// Key-value extraction from structured responses.
    Kval,
    /// JSON path extraction.
    Json,
    /// `XPath` extraction.
    Xpath,
    /// DSL expression.
    Dsl,
}

pub(crate) fn default_matcher_condition() -> MatcherCondition {
    MatcherCondition::Or
}

pub(crate) fn default_part() -> MatchPart {
    MatchPart::Body
}
