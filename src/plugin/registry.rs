use crate::plugin::traits::{
    Authenticator, CustomExtractor, CustomMatcher, CustomReporter, CustomTransform, DnsResolver,
    FindingStore, Plugin, PluginCapability, PostProcessor, ProtocolHandler, RateLimiter,
    ScanScheduler, TargetDiscovery, TemplateCompiler,
};
use rustc_hash::FxHashMap;

/// Registry of all installed plugins and their exported capabilities.
///
/// For keyed capabilities, later registrations replace earlier handlers for the same name.
pub struct PluginRegistry {
    plugins: Vec<Box<dyn Plugin>>,
    protocol_handlers: FxHashMap<String, Box<dyn ProtocolHandler>>,
    compilers: FxHashMap<String, Box<dyn TemplateCompiler>>,
    compiler_extensions: FxHashMap<String, String>,
    custom_matchers: FxHashMap<String, Box<dyn CustomMatcher>>,
    custom_extractors: FxHashMap<String, Box<dyn CustomExtractor>>,
    custom_transforms: FxHashMap<String, Box<dyn CustomTransform>>,
    reporters: FxHashMap<String, Box<dyn CustomReporter>>,
    post_processors: Vec<Box<dyn PostProcessor>>,
    discovery_sources: FxHashMap<String, Box<dyn TargetDiscovery>>,
    authenticators: FxHashMap<String, Box<dyn Authenticator>>,
    finding_stores: FxHashMap<String, Box<dyn FindingStore>>,
    rate_limiters: FxHashMap<String, Box<dyn RateLimiter>>,
    dns_resolvers: FxHashMap<String, Box<dyn DnsResolver>>,
    schedulers: FxHashMap<String, Box<dyn ScanScheduler>>,
}

impl PluginRegistry {
    /// Creates an empty plugin registry.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            protocol_handlers: FxHashMap::default(),
            compilers: FxHashMap::default(),
            compiler_extensions: FxHashMap::default(),
            custom_matchers: FxHashMap::default(),
            custom_extractors: FxHashMap::default(),
            custom_transforms: FxHashMap::default(),
            reporters: FxHashMap::default(),
            post_processors: Vec::new(),
            discovery_sources: FxHashMap::default(),
            authenticators: FxHashMap::default(),
            finding_stores: FxHashMap::default(),
            rate_limiters: FxHashMap::default(),
            dns_resolvers: FxHashMap::default(),
            schedulers: FxHashMap::default(),
        }
    }

    /// Registers a plugin and indexes all of the capabilities it exports.
    pub fn register(&mut self, plugin: Box<dyn Plugin>) {
        let capabilities = plugin.capabilities();
        self.plugins.push(plugin);

        for capability in capabilities {
            match capability {
                PluginCapability::Protocol { name, handler } => {
                    self.protocol_handlers.insert(normalize_key(&name), handler);
                }
                PluginCapability::Compiler { name, handler } => {
                    self.register_compiler(name, handler);
                }
                PluginCapability::Matcher { name, handler } => {
                    self.custom_matchers.insert(normalize_key(&name), handler);
                }
                PluginCapability::Extractor { name, handler } => {
                    self.custom_extractors.insert(normalize_key(&name), handler);
                }
                PluginCapability::Transform { name, handler } => {
                    self.custom_transforms.insert(normalize_key(&name), handler);
                }
                PluginCapability::Reporter { name, handler } => {
                    self.reporters.insert(normalize_key(&name), handler);
                }
                PluginCapability::PostProcessor { handler, .. } => {
                    self.post_processors.push(handler);
                }
                PluginCapability::Discovery { name, handler } => {
                    self.discovery_sources.insert(normalize_key(&name), handler);
                }
                PluginCapability::Auth { name, handler } => {
                    self.authenticators.insert(normalize_key(&name), handler);
                }
                PluginCapability::Store { name, handler } => {
                    self.finding_stores.insert(normalize_key(&name), handler);
                }
                PluginCapability::RateLimit { name, handler } => {
                    self.rate_limiters.insert(normalize_key(&name), handler);
                }
                PluginCapability::Dns { name, handler } => {
                    self.dns_resolvers.insert(normalize_key(&name), handler);
                }
                PluginCapability::Scheduler { name, handler } => {
                    self.schedulers.insert(normalize_key(&name), handler);
                }
            }
        }
    }

    /// Registers a compiler and maps each supported file extension to it.
    pub fn register_compiler(
        &mut self,
        name: impl Into<String>,
        handler: Box<dyn TemplateCompiler>,
    ) {
        let name = name.into();
        let normalized_name = normalize_key(&name);
        let extensions = handler
            .file_extensions()
            .iter()
            .map(|extension| normalize_extension(extension))
            .collect::<Vec<_>>();

        self.compilers.insert(normalized_name.clone(), handler);

        for extension in extensions {
            self.compiler_extensions
                .insert(extension, normalized_name.clone());
        }
    }

    /// Returns the protocol handler registered for the given name.
    pub fn protocol_handler(&self, name: &str) -> Option<&dyn ProtocolHandler> {
        self.protocol_handlers
            .get(&normalize_key(name))
            .map(Box::as_ref)
    }

    /// Returns the custom matcher registered for the given name.
    pub fn custom_matcher(&self, name: &str) -> Option<&dyn CustomMatcher> {
        self.custom_matchers
            .get(&normalize_key(name))
            .map(Box::as_ref)
    }

    /// Returns the compiler associated with the given file extension.
    pub fn compiler(&self, extension: &str) -> Option<&dyn TemplateCompiler> {
        let normalized_extension = normalize_extension(extension);
        let compiler_name = self.compiler_extensions.get(&normalized_extension)?;
        self.compilers.get(compiler_name).map(Box::as_ref)
    }

    /// Returns the custom extractor registered for the given name.
    pub fn custom_extractor(&self, name: &str) -> Option<&dyn CustomExtractor> {
        self.custom_extractors
            .get(&normalize_key(name))
            .map(Box::as_ref)
    }

    /// Returns the custom transform registered for the given name.
    pub fn custom_transform(&self, name: &str) -> Option<&dyn CustomTransform> {
        self.custom_transforms
            .get(&normalize_key(name))
            .map(Box::as_ref)
    }

    /// Returns the reporter registered for the given output format.
    pub fn reporter(&self, format: &str) -> Option<&dyn CustomReporter> {
        self.reporters.get(&normalize_key(format)).map(Box::as_ref)
    }

    /// Returns all registered post-processors in registration order.
    pub fn post_processors(&self) -> &[Box<dyn PostProcessor>] {
        &self.post_processors
    }

    /// Returns the target discovery source registered for the given name.
    pub fn discovery(&self, name: &str) -> Option<&dyn TargetDiscovery> {
        self.discovery_sources
            .get(&normalize_key(name))
            .map(Box::as_ref)
    }

    /// Returns the authenticator registered for the given name.
    pub fn authenticator(&self, name: &str) -> Option<&dyn Authenticator> {
        self.authenticators
            .get(&normalize_key(name))
            .map(Box::as_ref)
    }

    /// Returns the finding store registered for the given name.
    pub fn finding_store(&self, name: &str) -> Option<&dyn FindingStore> {
        self.finding_stores
            .get(&normalize_key(name))
            .map(Box::as_ref)
    }

    /// Returns the rate limiter registered for the given name.
    pub fn rate_limiter(&self, name: &str) -> Option<&dyn RateLimiter> {
        self.rate_limiters
            .get(&normalize_key(name))
            .map(Box::as_ref)
    }

    /// Returns the DNS resolver registered for the given name.
    pub fn dns_resolver(&self, name: &str) -> Option<&dyn DnsResolver> {
        self.dns_resolvers
            .get(&normalize_key(name))
            .map(Box::as_ref)
    }

    /// Returns the scan scheduler registered for the given name.
    pub fn scheduler(&self, name: &str) -> Option<&dyn ScanScheduler> {
        self.schedulers.get(&normalize_key(name)).map(Box::as_ref)
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_key(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

fn normalize_extension(extension: &str) -> String {
    extension
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::ScanMetadata;
    use crate::{
        Finding, FindingKind, Protocol, RequestDef, Result, Severity, Template, TemplateInfo,
        TemplateMeta,
    };
    use async_trait::async_trait;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct MockProtocolHandler {
        protocol: &'static str,
        template_name: &'static str,
    }

    #[async_trait]
    impl ProtocolHandler for MockProtocolHandler {
        async fn scan(&self, target: &str, template: &Template) -> Vec<Finding> {
            vec![Finding {
                template_id: template.id.clone(),
                template_name: self.template_name.to_string(),
                template_path: template.source_path.clone(),
                target: target.to_string(),
                severity: Severity::Info,
                kind: FindingKind::TechDetect,
                matched_values: vec![self.protocol.to_string()],
                extracted: HashMap::default(),
                matched_at: target.to_string(),
                request: None,
                response: None,
                curl_command: None,
                matcher_name: None,
                protocol: Some(format!("{:?}", template.protocol).to_ascii_lowercase()),
                timestamp: Utc::now(),
                tags: vec!["plugin".to_string()],
                description: None,
                references: Vec::new(),
                cve_ids: Vec::new(),
                confidence: None,
                verification: None,
            }]
        }

        fn protocol_name(&self) -> &str {
            self.protocol
        }
    }

    struct ContainsMatcher;

    impl CustomMatcher for ContainsMatcher {
        fn name(&self) -> &str {
            "contains"
        }

        fn matches(&self, data: &[u8], values: &[String], negative: bool) -> bool {
            let matched = values
                .iter()
                .any(|value| data.windows(value.len()).any(|w| w == value.as_bytes()));
            if negative {
                !matched
            } else {
                matched
            }
        }

        fn matched_values(&self, data: &[u8], values: &[String]) -> Vec<String> {
            values
                .iter()
                .filter(|value| data.windows(value.len()).any(|w| w == value.as_bytes()))
                .cloned()
                .collect()
        }
    }

    struct JsonReporter;

    struct MockCompiler;

    impl TemplateCompiler for MockCompiler {
        fn name(&self) -> &str {
            "mock"
        }

        fn file_extensions(&self) -> &[&str] {
            &["mock", ".mk"]
        }

        fn compile(&self, _source: &[u8], _path: &str) -> Result<Vec<Template>> {
            Ok(vec![template()])
        }
    }

    #[async_trait]
    impl CustomReporter for JsonReporter {
        fn name(&self) -> &str {
            "json reporter"
        }

        fn format(&self) -> &str {
            "json"
        }

        async fn report(&self, findings: &[Finding], metadata: &ScanMetadata) -> Result<Vec<u8>> {
            Ok(format!("{}:{}", findings.len(), metadata.targets_scanned).into_bytes())
        }
    }

    struct MarkerPostProcessor {
        invoked: Arc<AtomicBool>,
    }

    #[async_trait]
    impl PostProcessor for MarkerPostProcessor {
        fn name(&self) -> &str {
            "marker"
        }

        async fn process(&self, findings: &mut Vec<Finding>) {
            self.invoked.store(true, Ordering::SeqCst);
            for finding in findings {
                finding.tags.push("post-processed".to_string());
            }
        }
    }

    struct MockPlugin {
        id: &'static str,
        name: &'static str,
        version: &'static str,
        capabilities: std::sync::Mutex<Option<smallvec::SmallVec<[PluginCapability; 4]>>>,
    }

    impl MockPlugin {
        fn new(
            id: &'static str,
            name: &'static str,
            version: &'static str,
            capabilities: impl Into<smallvec::SmallVec<[PluginCapability; 4]>>,
        ) -> Self {
            Self {
                id,
                name,
                version,
                capabilities: std::sync::Mutex::new(Some(capabilities.into())),
            }
        }
    }

    impl Plugin for MockPlugin {
        fn id(&self) -> &str {
            self.id
        }

        fn name(&self) -> &str {
            self.name
        }

        fn version(&self) -> &str {
            self.version
        }

        fn capabilities(&self) -> smallvec::SmallVec<[PluginCapability; 4]> {
            self.capabilities
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .unwrap_or_default()
        }
    }

    fn template() -> Template {
        Template {
            id: "plugin-template".to_string(),
            ir_version: 1,
            extends: None,
            imports: Vec::new(),
            info: TemplateInfo {
                name: "Plugin Template".to_string(),
                author: vec!["karyx".to_string()],
                severity: Severity::Info,
                description: None,
                reference: Vec::new(),
                tags: vec!["plugin".to_string()],
                metadata: TemplateMeta::default(),
            },
            requests: vec![RequestDef {
                paths: vec!["/".to_string()],
                ..RequestDef::default()
            }],
            protocol: Protocol::Http,
            self_contained: false,
            variables: HashMap::default(),
            cli_variables: HashMap::default(),
            source_path: None,
            flow: None,
            workflows: Vec::new(),
            karyx_extensions: std::collections::HashMap::default(),
            parallel_groups: Vec::new(),
        }
    }

    #[tokio::test]
    async fn registers_mock_protocol_handler() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(MockPlugin::new(
            "proto",
            "protocol plugin",
            "1.0.0",
            vec![PluginCapability::Protocol {
                name: "mqtt".to_string(),
                handler: Box::new(MockProtocolHandler {
                    protocol: "mqtt",
                    template_name: "MQTT Detector",
                }),
            }],
        )));

        let handler = registry
            .protocol_handler("MQTT")
            .expect("operation should succeed");
        assert_eq!(handler.protocol_name(), "mqtt");

        let findings = handler.scan("mqtt://broker.local", &template()).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].template_name, "MQTT Detector");
    }

    #[test]
    fn registers_custom_matcher() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(MockPlugin::new(
            "matcher",
            "matcher plugin",
            "1.0.0",
            vec![PluginCapability::Matcher {
                name: "contains".to_string(),
                handler: Box::new(ContainsMatcher),
            }],
        )));

        let matcher = registry
            .custom_matcher("contains")
            .expect("operation should succeed");
        let values = vec!["admin".to_string(), "debug".to_string()];

        assert!(matcher.matches(b"panel=admin", &values, false));
        assert_eq!(
            matcher.matched_values(b"panel=admin", &values),
            vec!["admin".to_string()]
        );
    }

    #[tokio::test]
    async fn plugin_registry_lookup_returns_expected_handlers() {
        let mut registry = PluginRegistry::new();
        let invoked = Arc::new(AtomicBool::new(false));
        registry.register(Box::new(MockPlugin::new(
            "bundle",
            "bundle plugin",
            "1.0.0",
            smallvec::smallvec![
                PluginCapability::Reporter {
                    name: "json".to_string(),
                    handler: Box::new(JsonReporter),
                },
                PluginCapability::PostProcessor {
                    name: "marker".to_string(),
                    handler: Box::new(MarkerPostProcessor {
                        invoked: Arc::clone(&invoked),
                    }),
                },
            ],
        )));

        let reporter = registry.reporter("JSON").expect("operation should succeed");
        let rendered = reporter
            .report(
                &[],
                &ScanMetadata {
                    targets_scanned: 3,
                    ..Default::default()
                },
            )
            .await
            .expect("operation should succeed");
        assert_eq!(rendered, b"0:3");

        assert_eq!(registry.post_processors().len(), 1);
        let mut findings = vec![Finding::new(
            "id".to_string(),
            "name".to_string(),
            "https://example.com".to_string(),
            Severity::Info,
            "https://example.com".to_string(),
        )];
        registry.post_processors()[0].process(&mut findings).await;
        assert!(invoked.load(Ordering::SeqCst));
        assert!(findings[0].tags.iter().any(|tag| tag == "post-processed"));
    }

    #[test]
    fn later_plugins_override_overlapping_named_capabilities() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(MockPlugin::new(
            "first",
            "first plugin",
            "1.0.0",
            vec![PluginCapability::Matcher {
                name: "contains".to_string(),
                handler: Box::new(ContainsMatcher),
            }],
        )));
        registry.register(Box::new(MockPlugin::new(
            "second",
            "second plugin",
            "2.0.0",
            vec![PluginCapability::Matcher {
                name: "contains".to_string(),
                handler: Box::new(OverrideMatcher),
            }],
        )));

        let matcher = registry
            .custom_matcher("contains")
            .expect("operation should succeed");
        let values = vec!["admin".to_string()];
        assert!(!matcher.matches(b"admin", &values, false));
        assert_eq!(
            matcher.matched_values(b"admin", &values),
            Vec::<String>::new(),
            "override matcher should return no matched values when matches returns false"
        );
    }

    #[test]
    fn compiler_lookup_supports_extension_aliases() {
        let mut registry = PluginRegistry::new();
        registry.register_compiler("mock", Box::new(MockCompiler));

        assert_eq!(
            registry
                .compiler("mock")
                .expect("operation should succeed")
                .name(),
            "mock"
        );
        assert_eq!(
            registry
                .compiler(".mk")
                .expect("operation should succeed")
                .name(),
            "mock"
        );
        assert!(registry.compiler("yaml").is_none());
    }

    struct OverrideMatcher;

    impl CustomMatcher for OverrideMatcher {
        fn name(&self) -> &str {
            "contains"
        }

        fn matches(&self, _data: &[u8], _values: &[String], _negative: bool) -> bool {
            false
        }

        fn matched_values(&self, _data: &[u8], _values: &[String]) -> Vec<String> {
            Vec::new()
        }
    }
}
