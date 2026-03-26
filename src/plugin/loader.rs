//! Plugin loader implementation.
//!
//! Provides dynamic loading and management of secir plugins.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Errors that can occur during plugin loading.
#[derive(Debug, Clone)]
pub enum PluginLoadError {
    /// Plugin file not found.
    NotFound(PathBuf),
    /// Plugin file has invalid format or extension.
    InvalidFormat(String),
    /// Plugin failed validation checks.
    ValidationFailed(String),
    /// Duplicate plugin ID detected.
    DuplicateId(String),
    /// I/O error while reading plugin.
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
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    /// Unique identifier for the plugin.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Brief description of plugin functionality.
    pub description: String,
    /// Protocols this plugin can handle (if any).
    pub protocols: Vec<String>,
    /// Path to the plugin file/directory.
    pub path: PathBuf,
}

/// A loaded plugin with its metadata and handler.
#[derive(Debug)]
pub struct LoadedPlugin {
    /// Plugin metadata.
    pub metadata: PluginMetadata,
    /// Whether the plugin is currently active.
    pub active: bool,
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

    /// Load a plugin from a path.
    ///
    /// # Errors
    ///
    /// Returns `PluginLoadError` if:
    /// - The path doesn't exist
    /// - The plugin format is invalid
    /// - A plugin with the same ID is already loaded
    pub fn load(&mut self, path: &Path) -> Result<PluginMetadata, PluginLoadError> {
        // Verify path exists
        if !path.exists() {
            return Err(PluginLoadError::NotFound(path.to_path_buf()));
        }

        // Parse plugin metadata from the path
        let metadata = Self::parse_metadata(path)?;

        // Check for duplicate IDs
        if self.plugins.contains_key(&metadata.id) {
            return Err(PluginLoadError::DuplicateId(metadata.id.clone()));
        }

        // Validate the plugin
        Self::validate_plugin(&metadata, path)?;

        // Create and register the plugin
        let plugin = LoadedPlugin {
            metadata: metadata.clone(),
            active: true,
        };

        self.plugins.insert(metadata.id.clone(), plugin);

        Ok(metadata)
    }

    /// Load all plugins from a directory.
    ///
    /// Returns a tuple of (successfully loaded plugins, list of errors).
    pub fn load_directory(&mut self, dir: &Path) -> (Vec<PluginMetadata>, Vec<PluginLoadError>) {
        let mut loaded = Vec::new();
        let mut errors = Vec::new();

        if !dir.is_dir() {
            errors.push(PluginLoadError::NotFound(dir.to_path_buf()));
            return (loaded, errors);
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                errors.push(PluginLoadError::Io(e.to_string()));
                return (loaded, errors);
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    errors.push(PluginLoadError::Io(e.to_string()));
                    continue;
                }
            };

            let path = entry.path();
            
            // Skip non-file entries
            if !path.is_file() {
                continue;
            }

            // Attempt to load the plugin
            match self.load(&path) {
                Ok(meta) => loaded.push(meta),
                Err(e) => errors.push(e),
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
        self.plugins
            .get(id)
            .is_some_and(|plugin| plugin.active)
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
        self.plugins.values().map(|p| &p.metadata).collect()
    }

    /// Get all plugins that handle a specific protocol.
    pub fn plugins_for_protocol(&self, protocol: &str) -> Vec<&PluginMetadata> {
        self.plugins
            .values()
            .filter(|p| p.active && p.metadata.protocols.iter().any(|p| p == protocol))
            .map(|p| &p.metadata)
            .collect()
    }

    /// Parse metadata from a plugin path.
    fn parse_metadata(path: &Path) -> Result<PluginMetadata, PluginLoadError> {
        // For this implementation, we parse metadata from the filename
        // Format: {id}-{version}.{ext} or {id}.{ext}
        let filename = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| PluginLoadError::InvalidFormat("invalid filename".to_string()))?;

        // Parse ID and version from filename
        let (id, version) = if let Some((id_part, ver_part)) = filename.rsplit_once('-') {
            (id_part.to_string(), ver_part.to_string())
        } else {
            (filename.to_string(), "0.1.0".to_string())
        };

        // Validate ID format (alphanumeric, underscores, hyphens)
        if !id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return Err(PluginLoadError::InvalidFormat(format!(
                "invalid plugin ID: {id}"
            )));
        }

        Ok(PluginMetadata {
            id,
            name: filename.to_string(),
            version,
            description: String::new(),
            protocols: Vec::new(),
            path: path.to_path_buf(),
        })
    }

    /// Validate a plugin before loading.
    fn validate_plugin(metadata: &PluginMetadata, path: &Path) -> Result<(), PluginLoadError> {
        // Check that the file is readable
        if let Err(e) = std::fs::metadata(path) {
            return Err(PluginLoadError::Io(e.to_string()));
        }

        // Validate version format (simplified semver check)
        if metadata.version.split('.').count() < 2 {
            return Err(PluginLoadError::ValidationFailed(format!(
                "invalid version format: {}",
                metadata.version
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn registry_new_is_empty() {
        let registry = PluginRegistry::new();
        assert!(registry.list_plugins().is_empty());
    }

    #[test]
    fn load_nonexistent_fails() {
        let mut registry = PluginRegistry::new();
        let result = registry.load(Path::new("/nonexistent/plugin.so"));
        assert!(matches!(result, Err(PluginLoadError::NotFound(_))));
    }

    #[test]
    fn duplicate_id_fails() {
        let mut registry = PluginRegistry::new();
        
        // Create a temporary file
        let temp_dir = std::env::temp_dir();
        let plugin_path = temp_dir.join("test-plugin-1.0.so");
        
        // Write something to the file
        {
            let mut file = std::fs::File::create(&plugin_path).unwrap();
            file.write_all(b"test").unwrap();
        }
        
        // Load the first plugin
        let result = registry.load(&plugin_path);
        assert!(result.is_ok());
        
        // Try to load again (should fail with duplicate ID)
        let result = registry.load(&plugin_path);
        assert!(matches!(result, Err(PluginLoadError::DuplicateId(_))));
        
        // Cleanup
        let _ = std::fs::remove_file(&plugin_path);
    }

    #[test]
    fn enable_disable_plugin() {
        let mut registry = PluginRegistry::new();
        
        // Create a temporary file
        let temp_dir = std::env::temp_dir();
        let plugin_path = temp_dir.join("enable-test-1.0.so");
        
        {
            let mut file = std::fs::File::create(&plugin_path).unwrap();
            file.write_all(b"test").unwrap();
        }
        
        // Load and verify it's active
        let _ = registry.load(&plugin_path).unwrap();
        assert!(registry.is_active("enable-test"));
        
        // Disable and verify
        assert!(registry.disable("enable-test"));
        assert!(!registry.is_active("enable-test"));
        
        // Enable again
        assert!(registry.enable("enable-test"));
        assert!(registry.is_active("enable-test"));
        
        // Cleanup
        let _ = std::fs::remove_file(&plugin_path);
    }

    #[test]
    fn list_plugins_returns_all() {
        let mut registry = PluginRegistry::new();
        let temp_dir = std::env::temp_dir();
        
        // Create multiple plugins
        for i in 0..3 {
            let path = temp_dir.join(format!("list-test-{i}-1.0.so"));
            let mut file = std::fs::File::create(&path).unwrap();
            file.write_all(b"test").unwrap();
            let _ = registry.load(&path).unwrap();
        }
        
        // Verify all are listed
        let plugins = registry.list_plugins();
        assert_eq!(plugins.len(), 3);
        
        // Cleanup
        for i in 0..3 {
            let _ = std::fs::remove_file(temp_dir.join(format!("list-test-{i}-1.0.so")));
        }
    }
}
