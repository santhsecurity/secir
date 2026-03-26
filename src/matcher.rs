//! Shared matching data structures and response helpers used by match engines.

use crate::{MatchPart, MatcherDef, TemplateId};
use std::collections::HashMap;
use std::sync::OnceLock;

/// A confirmed match of a pattern against response data.
#[derive(Debug, Clone)]
pub struct Match {
    /// Which template this match belongs to.
    pub template_id: TemplateId,

    /// Index of the request within the template.
    pub request_index: usize,

    /// Index of the matcher within the request.
    pub matcher_index: usize,

    /// The original matcher definition (for diagnostics).
    pub matcher: MatcherDef,

    /// Which value within the matcher matched.
    pub value_index: usize,

    /// The actual value that matched.
    pub matched_value: String,

    /// Byte offset in the response where the match occurred.
    pub offset: usize,

    /// Whether this is a negative match (pattern found but matcher is inverted).
    /// When true, the presence of this match means the matcher FAILED.
    pub negative: bool,
}

/// A compiled database of all patterns from all templates.
///
/// Implementations fuse every word/regex/status matcher from every template
/// into a single matching automaton. One call to `scan()` evaluates ALL
/// patterns against the response simultaneously.
///
/// This is the core architectural advantage over Nuclei: N templates = 1 scan,
/// not N sequential scans.
pub trait MatchDatabase: Send + Sync {
    /// Scan response data against all compiled patterns.
    /// Returns all matches found in a single pass.
    #[must_use]
    fn scan(&self, response: &ResponseData) -> Vec<Match>;

    /// Number of patterns compiled into this database.
    fn pattern_count(&self) -> usize;

    /// Number of templates represented in this database.
    fn template_count(&self) -> usize;
}

/// Blanket impl so `Box<dyn MatchDatabase>` can be used as a `MatchDatabase`.
impl MatchDatabase for Box<dyn MatchDatabase> {
    fn scan(&self, response: &ResponseData) -> Vec<Match> {
        (**self).scan(response)
    }
    fn pattern_count(&self) -> usize {
        (**self).pattern_count()
    }
    fn template_count(&self) -> usize {
        (**self).template_count()
    }
}

/// The response data fed into the match engine.
/// Separates headers and body so matchers can target specific parts.
#[derive(Debug, Clone)]
pub struct ResponseData {
    /// HTTP status code.
    pub status: u16,

    /// Raw header bytes (lowercased for case-insensitive matching).
    pub headers: Vec<u8>,

    /// Individual header key-value pairs.
    pub header_map: Vec<(String, String)>,

    /// Case-insensitive lookup table for named headers.
    pub header_index: HashMap<String, usize>,

    /// Raw body bytes.
    pub body: Vec<u8>,

    /// Combined headers + body (for "all" matchers), built on first access.
    pub all: OnceLock<Vec<u8>>,

    /// Lossily-decoded body text block for evasion-resistant matching.
    pub body_text: OnceLock<Box<str>>,

    /// Lossily-decoded combined text block for evasion-resistant matching.
    pub all_text: OnceLock<Box<str>>,

    /// Source URL when known.
    pub url: Option<String>,

    /// Content length.
    pub content_length: usize,

    /// Time taken to collect this response.
    pub elapsed: std::time::Duration,
}

impl ResponseData {
    /// Build from raw parts.
    pub fn new(status: u16, header_map: Vec<(String, String)>, body: Vec<u8>) -> Self {
        let mut headers_buf = Vec::with_capacity(1024);
        let mut header_index = HashMap::with_capacity(header_map.len());
        for (key, value) in &header_map {
            let next_index = header_index.len();
            header_index
                .entry(key.to_ascii_lowercase())
                .or_insert(next_index);
            headers_buf.extend_from_slice(key.to_lowercase().as_bytes());
            headers_buf.extend_from_slice(b": ");
            headers_buf.extend_from_slice(value.as_bytes());
            headers_buf.push(b'\n');
        }

        let content_length = body.len();

        Self {
            status,
            headers: headers_buf,
            header_map,
            header_index,
            body,
            all: OnceLock::new(),
            body_text: OnceLock::new(),
            all_text: OnceLock::new(),
            url: None,
            content_length,
            elapsed: std::time::Duration::ZERO,
        }
    }

    /// Attach the elapsed time for the response.
    #[must_use]
    pub fn with_elapsed(mut self, elapsed: std::time::Duration) -> Self {
        self.elapsed = elapsed;
        self
    }

    /// Borrow the combined headers-and-body buffer, building it lazily on first access.
    pub fn all_bytes(&self) -> &[u8] {
        self.all.get_or_init(|| {
            let mut all = Vec::with_capacity(self.headers.len() + self.body.len());
            all.extend_from_slice(&self.headers);
            all.extend_from_slice(&self.body);
            all
        })
    }

    /// Borrow the response body as UTF-8 text, with lossy fallback for non-text payloads.
    pub fn body_str(&self) -> &str {
        if let Ok(s) = std::str::from_utf8(&self.body) {
            return s;
        }
        self.body_text.get_or_init(|| String::from_utf8_lossy(&self.body).into_owned().into_boxed_str())
    }

    /// Borrow the serialized headers as UTF-8 text, or an empty string when decoding fails.
    pub fn headers_str(&self) -> &str {
        std::str::from_utf8(&self.headers).unwrap_or("")
    }

    /// Borrow the combined headers-and-body buffer as UTF-8 text, with lossy fallback.
    pub fn all_str(&self) -> &str {
        let bytes = self.all_bytes();
        if let Ok(s) = std::str::from_utf8(bytes) {
            return s;
        }
        self.all_text.get_or_init(|| String::from_utf8_lossy(bytes).into_owned().into_boxed_str())
    }

    /// Release the combined headers-and-body buffer to free memory.
    pub fn release_all_bytes(&mut self) {
        self.all.take();
        self.all_text.take();
    }

    /// Attach the source URL to the response data.
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Borrow the response URL when known.
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }
}

/// Select a response part as text for matching or extraction.
pub fn select_response_part<'a>(response: &'a ResponseData, part: &MatchPart) -> &'a str {
    match part {
        MatchPart::Body => response.body_str(),
        MatchPart::Header => response.headers_str(),
        MatchPart::All => response.all_str(),
        MatchPart::Named(name) => response
            .header_index
            .get(&name.to_ascii_lowercase())
            .and_then(|index| response.header_map.get(*index))
            .map_or("", |(_, value)| value.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_data_builds_correctly() {
        let headers = vec![
            ("Content-Type".to_string(), "text/html".to_string()),
            ("Server".to_string(), "nginx/1.21".to_string()),
        ];
        let body = b"<html>hello</html>".to_vec();

        let data = ResponseData::new(200, headers, body.clone());

        assert_eq!(data.status, 200);
        assert_eq!(data.content_length, 18);
        assert_eq!(data.body, body);
        // Headers should be lowercased
        let header_str = String::from_utf8_lossy(&data.headers);
        assert!(header_str.contains("content-type: text/html"));
        assert!(header_str.contains("server: nginx/1.21"));
        assert!(data.all.get().is_none());
        assert!(data.all_bytes().len() > data.headers.len());
    }

    #[test]
    fn select_response_part_reads_named_headers_case_insensitively() {
        let data = ResponseData::new(
            200,
            vec![("Server".to_string(), "nginx".to_string())],
            b"body".to_vec(),
        );

        assert_eq!(select_response_part(&data, &MatchPart::Body), "body");
        assert_eq!(
            select_response_part(&data, &MatchPart::Named("server".into())),
            "nginx"
        );
        assert_eq!(
            select_response_part(&data, &MatchPart::Named("missing".into())),
            ""
        );
        assert_eq!(data.header_index.get("server"), Some(&0));
    }

    #[test]
    fn response_data_builds_all_lazily() {
        let data = ResponseData::new(
            200,
            vec![("Server".to_string(), "nginx".to_string())],
            b"body".to_vec(),
        );

        assert!(data.all.get().is_none());
        assert_eq!(
            select_response_part(&data, &MatchPart::All),
            "server: nginx\nbody"
        );
        assert!(data.all.get().is_some());
    }

    #[test]
    fn response_data_can_store_source_url() {
        let data = ResponseData::new(200, vec![], b"body".to_vec()).with_url("https://example.com");

        assert_eq!(data.url(), Some("https://example.com"));
    }
}
