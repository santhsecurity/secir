//! Error types for the Karyx template engine.
//!
//! All errors are centralized here so that crate boundaries can propagate
//! a single `karyx_core::Error` type through the `?` operator.

use crate::error_catalog::{entry_for, ErrorCatalogEntry};

/// Common result type used across Karyx crates.
pub type Result<T> = std::result::Result<T, Error>;

/// Error variants produced by template parsing, compilation, transport, and scanning.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Failed to parse a template file.
    TemplateParse {
        path: String,
        line: Option<usize>,
        expected: Option<String>,
        message: String,
        suggestion: Option<String>,
    },

    /// A template failed semantic validation.
    TemplateValidation { id: String, reason: String },

    /// Failed to compile a matcher pattern (e.g., invalid regex).
    PatternCompile { pattern: String, source: String },

    /// A transport-level error occurred during a network request.
    Transport {
        url: String,
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// An I/O error occurred.
    Io(std::io::Error),

    /// Failed to parse or serialize YAML data.
    Yaml {
        message: String,
        line: Option<usize>,
        column: Option<usize>,
    },

    /// Failed to parse or serialize JSON data.
    Json(serde_json::Error),

    /// DNS resolution failed for a target hostname.
    DnsResolution { hostname: String, message: String },

    /// An operation exceeded its time budget.
    Timeout,
}

impl Error {
    /// Constructs a template parse error with optional field and remediation details.
    pub fn template_parse(
        path: impl Into<String>,
        line: Option<usize>,
        expected: Option<impl Into<String>>,
        message: impl Into<String>,
        suggestion: Option<impl Into<String>>,
    ) -> Self {
        Self::TemplateParse {
            path: path.into(),
            line,
            expected: expected.map(Into::into),
            message: message.into(),
            suggestion: suggestion.map(Into::into),
        }
    }

    /// Return the stable error code and remediation guidance for this error.
    pub fn catalog_entry(&self) -> ErrorCatalogEntry {
        entry_for(self)
    }

    /// Return the stable error code for this error.
    pub fn code(&self) -> &'static str {
        self.catalog_entry().code
    }
}

fn line_suffix(line: Option<usize>) -> String {
    line.map(|line| format!(":{line}")).unwrap_or_default()
}

fn expected_suffix(expected: Option<&str>) -> String {
    expected
        .map(|expected| format!(" | expected: {expected}"))
        .unwrap_or_default()
}

fn suggestion_suffix(suggestion: Option<&str>) -> String {
    suggestion
        .map(|suggestion| format!(" | suggestion: {suggestion}"))
        .unwrap_or_default()
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] ", self.code())?;
        match self {
            Self::TemplateParse {
                path,
                line,
                expected,
                message,
                suggestion,
            } => write!(
                f,
                "template parse error in {path}{}: {message}{}{}",
                line_suffix(*line),
                expected_suffix(expected.as_deref()),
                suggestion_suffix(suggestion.as_deref()),
            ),
            Self::TemplateValidation { id, reason } => {
                write!(f, "invalid template {id}: {reason}")
            }
            Self::PatternCompile { pattern, source } => {
                write!(f, "pattern compilation failed for '{pattern}': {source}")
            }
            Self::Transport { url, message, .. } => {
                write!(f, "transport error for {url}: {message}")
            }
            Self::Io(error) => write!(f, "io error: {error}"),
            Self::Yaml {
                message,
                line,
                column,
            } => match (line, column) {
                (Some(line), Some(column)) => {
                    write!(f, "yaml error at line {line}, column {column}: {message}")
                }
                (Some(line), None) => write!(f, "yaml error at line {line}: {message}"),
                _ => write!(f, "yaml error: {message}"),
            },
            Self::Json(error) => write!(f, "json error: {error}"),
            Self::DnsResolution { hostname, message } => {
                write!(f, "dns resolution failed for {hostname}: {message}")
            }
            Self::Timeout => write!(f, "operation timed out"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport { source, .. } => source
                .as_deref()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_prefixes_catalog_code() {
        let error = Error::PatternCompile {
            pattern: "(".to_string(),
            source: "unclosed group".to_string(),
        };
        assert_eq!(error.code(), "KRX-003");
        assert!(error.to_string().starts_with("[KRX-003]"));
    }
}
