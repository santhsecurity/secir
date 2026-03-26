//! Plugin system for extending secir with runtime components.
//!
//! Load plugins from directories, enable/disable them at runtime,
//! and query the registry for active plugins.
//!
//! # Example
//!
//! ```
//! use secir::plugin::PluginRegistry;
//!
//! let registry = PluginRegistry::new();
//! assert_eq!(registry.list_plugins().len(), 0);
//! ```

pub mod loader;
pub mod registry;
pub mod traits;

pub use loader::{LoadedPlugin, PluginLoadError, PluginMetadata, PluginRegistry};
pub use traits::*;
