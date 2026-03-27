// Pattern system for secir
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Errors encountered while loading pattern files.
#[derive(Debug)]
pub enum PatternLoadError {
    /// The specified path is not a directory.
    NotADirectory(PathBuf),
    /// IO error reading a file or directory.
    Io(PathBuf, std::io::Error),
    /// TOML parse error in a pattern file.
    Parse(PathBuf, String),
}

impl std::fmt::Display for PatternLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotADirectory(p) => write!(f, "not a directory: {}", p.display()),
            Self::Io(p, e) => write!(f, "{}: {e}", p.display()),
            Self::Parse(p, e) => write!(f, "parse error in {}: {e}", p.display()),
        }
    }
}

impl std::error::Error for PatternLoadError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternCategory {
    JsEndpoint,
    ApiDocPath,
    WafKeyword,
    ErrorKeyword,
    TechSignature,
    HiddenPath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub name: String,
    pub value: String,
    pub category: PatternCategory,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct PatternSet {
    pub js_endpoints: Vec<Pattern>,
    pub api_doc_paths: Vec<Pattern>,
    pub waf_keywords: Vec<Pattern>,
    pub error_keywords: Vec<Pattern>,
    pub tech_signatures: Vec<Pattern>,
    pub hidden_paths: Vec<Pattern>,
}

#[derive(Debug, Deserialize)]
struct PatternConfig {
    #[serde(default)]
    patterns: Vec<Pattern>,
}

const DEFAULTS_TOML: &str = include_str!("../data/patterns/defaults.toml");

impl Default for PatternSet {
    /// Create a new `PatternSet` with default patterns loaded from embedded TOML.
    ///
    /// Uses an empty set if the embedded defaults.toml is somehow malformed
    /// (defensive fallback that should never happen in practice).
    fn default() -> Self {
        // Parse embedded TOML; use empty set if somehow malformed (defensive)
        let config: PatternConfig = toml::from_str(DEFAULTS_TOML).unwrap_or_else(|e| {
            eprintln!("Warning: failed to parse embedded defaults.toml: {e}");
            PatternConfig {
                patterns: Vec::new(),
            }
        });

        let mut set = PatternSet {
            js_endpoints: Vec::new(),
            api_doc_paths: Vec::new(),
            waf_keywords: Vec::new(),
            error_keywords: Vec::new(),
            tech_signatures: Vec::new(),
            hidden_paths: Vec::new(),
        };
        for pattern in config.patterns {
            set.add_pattern(pattern);
        }
        set
    }
}

impl PatternSet {
    fn add_pattern(&mut self, pattern: Pattern) {
        match pattern.category {
            PatternCategory::JsEndpoint => self.js_endpoints.push(pattern),
            PatternCategory::ApiDocPath => self.api_doc_paths.push(pattern),
            PatternCategory::WafKeyword => self.waf_keywords.push(pattern),
            PatternCategory::ErrorKeyword => self.error_keywords.push(pattern),
            PatternCategory::TechSignature => self.tech_signatures.push(pattern),
            PatternCategory::HiddenPath => self.hidden_paths.push(pattern),
        }
    }

    /// Load user pattern overrides from a directory of TOML files.
    ///
    /// Returns the pattern set and a list of errors encountered while loading.
    /// Errors are collected (not swallowed) so callers can decide how to handle them.
    pub fn load_user_overrides(dir: &Path) -> (Self, Vec<PatternLoadError>) {
        let mut set = Self::default();
        let mut errors = Vec::new();

        if !dir.is_dir() {
            errors.push(PatternLoadError::NotADirectory(dir.to_path_buf()));
            return (set, errors);
        }

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                errors.push(PatternLoadError::Io(dir.to_path_buf(), e));
                return (set, errors);
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    errors.push(PatternLoadError::Io(dir.to_path_buf(), e));
                    continue;
                }
            };
            let path = entry.path();
            if !path.is_file() || path.extension().map_or(true, |e| e != "toml") {
                continue;
            }
            let content = match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    errors.push(PatternLoadError::Io(path, e));
                    continue;
                }
            };
            match toml::from_str::<PatternConfig>(&content) {
                Ok(config) => {
                    for pattern in config.patterns {
                        set.add_pattern(pattern);
                    }
                }
                Err(e) => {
                    errors.push(PatternLoadError::Parse(path, e.to_string()));
                }
            }
        }
        (set, errors)
    }
    pub fn patterns_for(&self, category: PatternCategory) -> &[Pattern] {
        match category {
            PatternCategory::JsEndpoint => &self.js_endpoints,
            PatternCategory::ApiDocPath => &self.api_doc_paths,
            PatternCategory::WafKeyword => &self.waf_keywords,
            PatternCategory::ErrorKeyword => &self.error_keywords,
            PatternCategory::TechSignature => &self.tech_signatures,
            PatternCategory::HiddenPath => &self.hidden_paths,
        }
    }
}
