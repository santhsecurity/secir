//! Plugin artifact loader implementation.
//!
//! This module loads plugin manifests directly and can also load shared-library
//! plugin artifacts when the library is accompanied by a sidecar manifest.

use libloading::Library;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const DEFAULT_MANIFEST_NAME: &str = "secir-plugin.toml";

/// Errors that can occur during plugin loading.
#[derive(Debug)]
pub enum PluginLoadError {
    /// Plugin file or directory not found.
    NotFound(PathBuf),
    /// Plugin file has invalid format or extension.
    InvalidFormat(String),
    /// Plugin metadata failed validation checks.
    ValidationFailed(String),
    /// Duplicate plugin ID detected.
    DuplicateId(String),
    /// I/O error while reading plugin metadata or artifacts.
    Io(String),
}

impl std::fmt::Display for PluginLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(p) => write!(f, "plugin not found: {}", p.display()),
            Self::InvalidFormat(s) => write!(f, "invalid plugin format: {s}"),
            Self::ValidationFailed(s) => write!(f, "plugin validation failed: {s}"),
            Self::DuplicateId(id) => write!(f, "duplicate plugin ID: {id}"),
            Self::Io(s) => write!(f, "I/O error: {s}"),
        }
    }
}

impl std::error::Error for PluginLoadError {}

/// Metadata for a loaded plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// Unique identifier for the plugin.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Brief description of plugin functionality.
    #[serde(default)]
    pub description: String,
    /// Protocols this plugin can handle (if any).
    #[serde(default)]
    pub protocols: Vec<String>,
    /// Path to the plugin manifest or binary.
    #[serde(default)]
    pub path: PathBuf,
    /// Optional path to the executable plugin artifact.
    #[serde(default)]
    pub library_path: Option<PathBuf>,
}

#[derive(Debug)]
enum PluginArtifact {
    ManifestOnly,
    DynamicLibrary(Library),
}

/// A loaded plugin with its metadata and loaded artifact.
#[derive(Debug)]
pub struct LoadedPlugin {
    /// Plugin metadata.
    pub metadata: PluginMetadata,
    /// Whether the plugin is currently active.
    pub active: bool,
    artifact: PluginArtifact,
}

impl LoadedPlugin {
    /// Returns true when this entry has a loaded shared library handle.
    #[must_use]
    pub fn has_dynamic_library(&self) -> bool {
        match &self.artifact {
            PluginArtifact::ManifestOnly => false,
            PluginArtifact::DynamicLibrary(library) => {
                let _ = library;
                true
            }
        }
    }
}

/// Registry of loaded plugins.
#[derive(Debug, Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, LoadedPlugin>,
}

impl PluginRegistry {
    /// Create a new empty plugin registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Load a plugin manifest, package directory, or shared library.
    ///
    /// Package directories must contain `secir-plugin.toml`.
    /// Shared libraries must have a sibling manifest file using the same stem and
    /// either a `.toml` or `.json` extension.
    ///
    /// # Errors
    ///
    /// Returns `PluginLoadError` if:
    /// - The path doesn't exist
    /// - The plugin format is invalid
    /// - The manifest cannot be parsed
    /// - The shared library cannot be opened
    /// - A plugin with the same ID is already loaded
    pub fn load(&mut self, path: &Path) -> Result<PluginMetadata, PluginLoadError> {
        if !path.exists() {
            return Err(PluginLoadError::NotFound(path.to_path_buf()));
        }

        let (metadata, artifact) = Self::load_artifact(path)?;

        if self.plugins.contains_key(&metadata.id) {
            return Err(PluginLoadError::DuplicateId(metadata.id.clone()));
        }

        Self::validate_plugin(&metadata)?;

        let plugin = LoadedPlugin {
            metadata: metadata.clone(),
            active: true,
            artifact,
        };
        self.plugins.insert(metadata.id.clone(), plugin);

        Ok(metadata)
    }

    /// Load all plugin entries from a directory.
    ///
    /// The directory may contain standalone manifests, package directories, and
    /// shared libraries accompanied by sidecar manifests.
    pub fn load_directory(&mut self, dir: &Path) -> (Vec<PluginMetadata>, Vec<PluginLoadError>) {
        let mut loaded = Vec::new();
        let mut errors = Vec::new();

        if !dir.is_dir() {
            errors.push(PluginLoadError::NotFound(dir.to_path_buf()));
            return (loaded, errors);
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) => {
                errors.push(PluginLoadError::Io(error.to_string()));
                return (loaded, errors);
            }
        };

        for entry in entries {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(error) => {
                    errors.push(PluginLoadError::Io(error.to_string()));
                    continue;
                }
            };

            if !Self::is_candidate_plugin_entry(&path) {
                continue;
            }

            match self.load(&path) {
                Ok(metadata) => loaded.push(metadata),
                Err(error) => errors.push(error),
            }
        }

        (loaded, errors)
    }

    /// Unload a plugin by ID.
    pub fn unload(&mut self, id: &str) -> Option<LoadedPlugin> {
        self.plugins.remove(id)
    }

    /// Get a reference to a loaded plugin.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&LoadedPlugin> {
        self.plugins.get(id)
    }

    /// Check if a plugin is loaded and active.
    #[must_use]
    pub fn is_active(&self, id: &str) -> bool {
        self.plugins.get(id).is_some_and(|plugin| plugin.active)
    }

    /// Enable a previously disabled plugin.
    pub fn enable(&mut self, id: &str) -> bool {
        if let Some(plugin) = self.plugins.get_mut(id) {
            plugin.active = true;
            true
        } else {
            false
        }
    }

    /// Disable a plugin without unloading it.
    pub fn disable(&mut self, id: &str) -> bool {
        if let Some(plugin) = self.plugins.get_mut(id) {
            plugin.active = false;
            true
        } else {
            false
        }
    }

    /// Get all loaded plugin metadata.
    pub fn list_plugins(&self) -> Vec<&PluginMetadata> {
        self.plugins.values().map(|plugin| &plugin.metadata).collect()
    }

    /// Get all plugins that handle a specific protocol.
    pub fn plugins_for_protocol(&self, protocol: &str) -> Vec<&PluginMetadata> {
        self.plugins
            .values()
            .filter(|plugin| {
                plugin.active
                    && plugin
                        .metadata
                        .protocols
                        .iter()
                        .any(|candidate| candidate == protocol)
            })
            .map(|plugin| &plugin.metadata)
            .collect()
    }

    fn load_artifact(path: &Path) -> Result<(PluginMetadata, PluginArtifact), PluginLoadError> {
        if path.is_dir() {
            let manifest_path = path.join(DEFAULT_MANIFEST_NAME);
            let mut metadata = Self::read_manifest(&manifest_path)?;
            metadata.path = manifest_path;
            if let Some(library_path) = metadata.library_path.clone() {
                let library_path = resolve_relative_to(path, &library_path);
                metadata.library_path = Some(library_path.clone());
                return Ok((
                    metadata,
                    PluginArtifact::DynamicLibrary(Self::open_library(&library_path)?),
                ));
            }
            return Ok((metadata, PluginArtifact::ManifestOnly));
        }

        if Self::is_manifest_path(path) {
            let mut metadata = Self::read_manifest(path)?;
            metadata.path = path.to_path_buf();
            if let Some(library_path) = metadata.library_path.clone() {
                let library_path = resolve_relative_to(
                    path.parent().unwrap_or_else(|| Path::new(".")),
                    &library_path,
                );
                metadata.library_path = Some(library_path.clone());
                return Ok((
                    metadata,
                    PluginArtifact::DynamicLibrary(Self::open_library(&library_path)?),
                ));
            }
            return Ok((metadata, PluginArtifact::ManifestOnly));
        }

        if !Self::is_dynamic_library_path(path) {
            return Err(PluginLoadError::InvalidFormat(format!(
                "unsupported plugin entry '{}'",
                path.display()
            )));
        }

        let manifest_path = Self::find_sidecar_manifest(path)?;
        let mut metadata = Self::read_manifest(&manifest_path)?;
        metadata.path = path.to_path_buf();
        metadata.library_path = Some(path.to_path_buf());

        Ok((
            metadata,
            PluginArtifact::DynamicLibrary(Self::open_library(path)?),
        ))
    }

    fn read_manifest(path: &Path) -> Result<PluginMetadata, PluginLoadError> {
        if !path.exists() {
            return Err(PluginLoadError::NotFound(path.to_path_buf()));
        }

        let contents =
            std::fs::read_to_string(path).map_err(|error| PluginLoadError::Io(error.to_string()))?;

        let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or_default();
        let mut metadata = match extension {
            "toml" => toml::from_str::<PluginMetadata>(&contents)
                .map_err(|error| PluginLoadError::InvalidFormat(error.to_string()))?,
            "json" => serde_json::from_str::<PluginMetadata>(&contents)
                .map_err(|error| PluginLoadError::InvalidFormat(error.to_string()))?,
            _ => {
                return Err(PluginLoadError::InvalidFormat(format!(
                    "unsupported manifest format '{}'",
                    path.display()
                )))
            }
        };

        if metadata.path.as_os_str().is_empty() {
            metadata.path = path.to_path_buf();
        }

        Ok(metadata)
    }

    fn validate_plugin(metadata: &PluginMetadata) -> Result<(), PluginLoadError> {
        if metadata.id.is_empty() {
            return Err(PluginLoadError::ValidationFailed(
                "plugin ID must not be empty".to_string(),
            ));
        }

        if !metadata
            .id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        {
            return Err(PluginLoadError::ValidationFailed(format!(
                "invalid plugin ID '{}'",
                metadata.id
            )));
        }

        if metadata.name.trim().is_empty() {
            return Err(PluginLoadError::ValidationFailed(
                "plugin name must not be empty".to_string(),
            ));
        }

        let version_parts: Vec<_> = metadata.version.split('.').collect();
        if version_parts.len() < 3 || version_parts.iter().any(|part| part.parse::<u64>().is_err())
        {
            return Err(PluginLoadError::ValidationFailed(format!(
                "invalid semantic version '{}'",
                metadata.version
            )));
        }

        if let Some(library_path) = &metadata.library_path {
            if !library_path.exists() {
                return Err(PluginLoadError::ValidationFailed(format!(
                    "declared library '{}' does not exist",
                    library_path.display()
                )));
            }
        }

        Ok(())
    }

    fn find_sidecar_manifest(path: &Path) -> Result<PathBuf, PluginLoadError> {
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| PluginLoadError::InvalidFormat("invalid plugin filename".to_string()))?;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));

        for extension in ["toml", "json"] {
            let candidate = dir.join(format!("{stem}.{extension}"));
            if candidate.exists() {
                return Ok(candidate);
            }
        }

        Err(PluginLoadError::NotFound(dir.join(format!("{stem}.toml"))))
    }

    fn open_library(path: &Path) -> Result<Library, PluginLoadError> {
        // SAFETY: loading a shared library is inherently unsafe. The loader keeps
        // the handle alive for the lifetime of the registry entry and does not
        // dereference arbitrary symbols here.
        unsafe { Library::new(path) }
            .map_err(|error| PluginLoadError::ValidationFailed(error.to_string()))
    }

    fn is_manifest_path(path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| matches!(ext, "toml" | "json"))
    }

    fn is_dynamic_library_path(path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| matches!(ext, "so" | "dylib" | "dll"))
    }

    fn is_candidate_plugin_entry(path: &Path) -> bool {
        path.is_dir() || Self::is_manifest_path(path) || Self::is_dynamic_library_path(path)
    }
}

fn resolve_relative_to(base: &Path, candidate: &Path) -> PathBuf {
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_manifest(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn registry_new_is_empty() {
        let registry = PluginRegistry::new();
        assert!(registry.list_plugins().is_empty());
    }

    #[test]
    fn load_nonexistent_fails() {
        let mut registry = PluginRegistry::new();
        let result = registry.load(Path::new("/nonexistent/plugin.toml"));
        assert!(matches!(result, Err(PluginLoadError::NotFound(_))));
    }

    #[test]
    fn load_manifest_plugin_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("plugin.toml");
        write_manifest(
            &manifest_path,
            r#"
id = "example-plugin"
name = "Example Plugin"
version = "1.2.3"
description = "manifest plugin"
protocols = ["http", "dns"]
"#,
        );

        let mut registry = PluginRegistry::new();
        let metadata = registry.load(&manifest_path).unwrap();

        assert_eq!(metadata.id, "example-plugin");
        assert_eq!(metadata.protocols, vec!["http", "dns"]);
        assert!(!registry.get("example-plugin").unwrap().has_dynamic_library());
    }

    #[test]
    fn duplicate_id_fails() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.toml");
        let second = dir.path().join("second.toml");

        write_manifest(
            &first,
            r#"
id = "dupe-plugin"
name = "Plugin One"
version = "1.0.0"
"#,
        );
        write_manifest(
            &second,
            r#"
id = "dupe-plugin"
name = "Plugin Two"
version = "1.0.0"
"#,
        );

        let mut registry = PluginRegistry::new();
        assert!(registry.load(&first).is_ok());
        let result = registry.load(&second);
        assert!(matches!(result, Err(PluginLoadError::DuplicateId(_))));
    }

    #[test]
    fn enable_disable_plugin() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("toggle.toml");
        write_manifest(
            &manifest_path,
            r#"
id = "toggle-plugin"
name = "Toggle Plugin"
version = "1.0.0"
"#,
        );

        let mut registry = PluginRegistry::new();
        registry.load(&manifest_path).unwrap();
        assert!(registry.is_active("toggle-plugin"));
        assert!(registry.disable("toggle-plugin"));
        assert!(!registry.is_active("toggle-plugin"));
        assert!(registry.enable("toggle-plugin"));
        assert!(registry.is_active("toggle-plugin"));
    }

    #[test]
    fn load_directory_discovers_manifests_and_packages() {
        let dir = tempfile::tempdir().unwrap();
        write_manifest(
            &dir.path().join("first.toml"),
            r#"
id = "first-plugin"
name = "First Plugin"
version = "1.0.0"
"#,
        );

        let package_dir = dir.path().join("pkg");
        std::fs::create_dir(&package_dir).unwrap();
        write_manifest(
            &package_dir.join(DEFAULT_MANIFEST_NAME),
            r#"
id = "second-plugin"
name = "Second Plugin"
version = "1.0.0"
protocols = ["dns"]
"#,
        );

        let mut registry = PluginRegistry::new();
        let (loaded, errors) = registry.load_directory(dir.path());

        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        assert_eq!(loaded.len(), 2);
        assert_eq!(registry.plugins_for_protocol("dns").len(), 1);
    }
}
