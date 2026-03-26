//! Stable error catalog for user-facing Karyx errors.

use crate::Error;

/// A documented, stable error entry users can search for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCatalogEntry {
    /// Stable error code such as `KRX-001`.
    pub code: &'static str,
    /// Human-readable explanation of the failure class.
    pub explanation: &'static str,
    /// Suggested user action to remediate or investigate the issue.
    pub suggested_fix: &'static str,
}

pub const TEMPLATE_PARSE: ErrorCatalogEntry = ErrorCatalogEntry {
    code: "KRX-001",
    explanation: "A template file could not be parsed into Karyx's internal representation.",
    suggested_fix: "Check the template syntax, required fields, indentation, and encoding near the reported location.",
};

pub const TEMPLATE_VALIDATION: ErrorCatalogEntry = ErrorCatalogEntry {
    code: "KRX-002",
    explanation: "A template parsed successfully but failed semantic validation.",
    suggested_fix: "Review the template's required metadata, protocol fields, and matcher structure.",
};

pub const PATTERN_COMPILE: ErrorCatalogEntry = ErrorCatalogEntry {
    code: "KRX-003",
    explanation: "A matcher or pattern could not be compiled before scanning.",
    suggested_fix: "Fix the invalid regex or pattern syntax and re-run validation or linting.",
};

pub const TRANSPORT: ErrorCatalogEntry = ErrorCatalogEntry {
    code: "KRX-004",
    explanation: "A network transport operation failed while preparing or sending a request.",
    suggested_fix: "Check the target URL, network reachability, TLS/proxy settings, and retry or rate-limit configuration.",
};

pub const IO: ErrorCatalogEntry = ErrorCatalogEntry {
    code: "KRX-005",
    explanation: "Karyx could not read from or write to a filesystem or stream resource.",
    suggested_fix: "Verify the path exists and that Karyx has the required permissions and disk access.",
};

pub const YAML: ErrorCatalogEntry = ErrorCatalogEntry {
    code: "KRX-006",
    explanation: "YAML data could not be parsed or serialized.",
    suggested_fix: "Validate the YAML structure and ensure values use valid YAML syntax.",
};

pub const JSON: ErrorCatalogEntry = ErrorCatalogEntry {
    code: "KRX-007",
    explanation: "JSON data could not be parsed or serialized.",
    suggested_fix: "Validate the JSON payload and ensure it is well-formed UTF-8 JSON.",
};

pub const DNS_RESOLUTION: ErrorCatalogEntry = ErrorCatalogEntry {
    code: "KRX-008",
    explanation: "DNS resolution failed for the target hostname.",
    suggested_fix: "Check your network connection and DNS configuration, or verify the hostname exists.",
};

pub const TIMEOUT: ErrorCatalogEntry = ErrorCatalogEntry {
    code: "KRX-009",
    explanation: "An operation exceeded its time budget.",
    suggested_fix: "Increase the timeout or check if the target is unresponsive.",
};

/// All documented error entries.
pub const ALL_ERROR_CATALOG: [ErrorCatalogEntry; 9] = [
    TEMPLATE_PARSE,
    TEMPLATE_VALIDATION,
    PATTERN_COMPILE,
    TRANSPORT,
    IO,
    YAML,
    JSON,
    DNS_RESOLUTION,
    TIMEOUT,
];

/// Resolve the stable catalog entry for a concrete error value.
pub fn entry_for(error: &Error) -> ErrorCatalogEntry {
    match error {
        Error::TemplateParse { .. } => TEMPLATE_PARSE,
        Error::TemplateValidation { .. } => TEMPLATE_VALIDATION,
        Error::PatternCompile { .. } => PATTERN_COMPILE,
        Error::Transport { .. } => TRANSPORT,
        Error::Io(_) => IO,
        Error::Yaml { .. } => YAML,
        Error::Json(_) => JSON,
        Error::DnsResolution { .. } => DNS_RESOLUTION,
        Error::Timeout => TIMEOUT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn error_catalog_codes_are_unique() {
        let codes: HashSet<_> = ALL_ERROR_CATALOG.iter().map(|entry| entry.code).collect();
        assert_eq!(codes.len(), ALL_ERROR_CATALOG.len());
    }
}
