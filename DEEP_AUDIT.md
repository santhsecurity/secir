# SECIR Deep Audit Report

**Date:** 2026-03-26  
**Auditor:** Kimi Code CLI  
**Crate:** secir (Security Intermediate Representation)  
**Location:** `/home/mukund-thiru/Santh/libs/scanner/secir/`  
**Size:** ~4,930 lines of Rust code (17 source files)  
**Test Status:** ✅ All 48 tests pass + 1 doc-test pass

---

## Executive Summary

secir is the **universal type vocabulary** for ALL Santh security scanning tools. It defines the shared IR between frontends (template compilers) and backends (scan executors). The codebase is structurally sound, well-tested, but has significant gaps between its ambitious architecture and actual implementation. Several critical features are **declared but not implemented**.

**Verdict:** The foundation is solid, but this is a **types-only crate** — it defines interfaces and data structures but contains **zero actual scanning logic**. This is by design for an IR crate, but some advertised features are pure stubs.

---

## 1. Core Types Analysis

### 1.1 Template (`template/mod.rs`, 628 lines)

**Status:** ✅ **COMPLETE AND CORRECT**

The `Template` struct is the crown jewel — comprehensive, well-designed, and properly serializable:

```rust
pub struct Template {
    pub id: TemplateId,                    // ✅ Unique identifier
    pub ir_version: u32,                   // ✅ Forward compatibility
    pub extends: Option<String>,           // ✅ Template inheritance
    pub imports: Vec<TemplateImport>,      // ✅ Modularity support
    pub info: TemplateInfo,                // ✅ Rich metadata
    pub requests: Vec<RequestDef>,         // ✅ Multi-request sequences
    pub protocol: Protocol,                // ✅ 10 protocol variants
    pub self_contained: bool,              // ✅ Embedded targets
    pub variables: HashMap<String, String>, // ✅ Template-level vars
    pub cli_variables: HashMap<String, String>, // ✅ Runtime overrides
    pub source_path: Option<String>,       // ✅ Debug/provenance
    pub flow: Option<String>,              // ✅ Nuclei flow expressions
    pub workflows: Vec<Workflow>,          // ✅ Template chaining
    pub karyx_extensions: HashMap<String, serde_json::Value>, // ✅ Extensibility
    pub parallel_groups: Vec<ParallelGroup>, // ✅ Parallel execution hints
}
```

**Strengths:**
- `TemplateBuilder` provides ergonomic programmatic construction with validation
- `Template::classify()` auto-categorizes findings from tags (8 category rules)
- Full JSON roundtrip serialization verified by tests
- Protocol enum covers HTTP, DNS, TCP, SSL, WebSocket, Headless, Code, File, Whois, JavaScript

**Weaknesses:**
- `extends` field exists but **no inheritance resolution logic** exists anywhere
- `flow` field exists but **no flow expression parser** exists
- `parallel_groups` exists but **no parallel execution semantics** defined

### 1.2 Finding (`finding.rs`, 336 lines)

**Status:** ✅ **COMPLETE AND CORRECT**

Rich finding structure with 20 fields covering:
- Identity: `template_id`, `template_name`, `target`, `matched_at`
- Evidence: `matched_values`, `extracted`, `request`, `response`, `curl_command`
- Classification: `severity`, `kind` (8 FindingKind variants), `tags`, `cve_ids`
- Metadata: `timestamp`, `description`, `references`, `confidence`
- Provenance: `template_path`, `matcher_name`, `protocol`
- Replay: `verification` (hidden field for reproducibility)

**`Finding::from_template()`** — The killer helper:
```rust
pub fn from_template(template: &Template, target: String, matched_at: String, matched_values: Vec<String>) -> Self
```
This eliminates 6 lines of boilerplate per finding site. Smart design.

**`calculate_confidence()`** — Statistical scoring (0.5-0.95) based on:
- Extractor presence
- Multiple AND matchers
- Status + Word AND combo
- Regex with capture groups

### 1.3 Severity (`severity.rs`, 47 lines)

**Status:** ✅ **COMPLETE AND MINIMAL**

6-level CVSS-aligned enum with proper `PartialOrd` for comparisons:
```rust
Unknown < Info < Low < Medium < High < Critical
```

Serializes to lowercase strings (Nuclei-compatible). Could benefit from CVSS score integration but that's in `TemplateMeta`.

---

## 2. Plugin System Analysis

### 2.1 Plugin Traits (`plugin/traits.rs`, 414 lines)

**Status:** ⚠️ **REAL BUT UNIMPLEMENTED BEYOND TRAITS**

**12 Plugin Capability Traits Defined:**

| Trait | Status | Notes |
|-------|--------|-------|
| `ProtocolHandler` | ✅ Trait defined | No built-in implementations |
| `TemplateCompiler` | ✅ Trait defined | No built-in implementations |
| `CustomMatcher` | ✅ Trait defined | No built-in implementations |
| `CustomExtractor` | ✅ Trait defined | No built-in implementations |
| `CustomTransform` | ✅ Trait defined | No built-in implementations |
| `CustomReporter` | ✅ Trait defined | No built-in implementations |
| `PostProcessor` | ✅ Trait defined | No built-in implementations |
| `TargetDiscovery` | ✅ Trait defined | No built-in implementations |
| `Authenticator` | ✅ Trait defined | No built-in implementations |
| `FindingStore` | ✅ Trait defined | No built-in implementations |
| `RateLimiter` | ✅ Trait defined | No built-in implementations |
| `DnsResolver` | ✅ Trait defined | No built-in implementations |
| `ScanScheduler` | ✅ Trait defined | No built-in implementations |

**The plugin system is NOT a stub** — it's a legitimate trait-based extension mechanism with:
- `PluginCapability` enum for capability advertisement
- `Plugin` base trait with metadata
- Proper `Send + Sync` bounds for async execution
- `async_trait` where needed

**However:** There are **ZERO built-in implementations**. Every trait must be implemented by downstream crates. This is architecturally correct for an IR crate, but the README implies more capability than exists.

### 2.2 Plugin Registry (`plugin/registry.rs`, 598 lines)

**Status:** ✅ **FULLY IMPLEMENTED**

`PluginRegistry` properly manages:
- `Vec<Box<dyn Plugin>>` — all registered plugins
- `FxHashMap<String, Box<dyn ProtocolHandler>>` — protocol handlers by name
- `FxHashMap<String, Box<dyn TemplateCompiler>>` — compilers by name
- `FxHashMap<String, Box<dyn CustomMatcher>>` — matchers by name
- And 8 more capability maps...

**Key Features:**
- `register()` — indexes all capabilities from a plugin
- Later plugins override earlier ones for same-named capabilities
- Extension-to-compiler mapping for file type dispatch
- Uses `rustc_hash::FxHashMap` for performance

**Tests verify:** Protocol handler registration, custom matcher registration, compiler extension aliasing, post-processor invocation, plugin override behavior.

### 2.3 Plugin Loader (`plugin/loader.rs`, 360 lines)

**Status:** ⚠️ **PARTIALLY IMPLEMENTED — STUB LOADING**

**CRITICAL ISSUE:** The loader does **NOT actually load dynamic libraries**. It:
1. Reads file metadata from filesystem
2. Parses plugin ID and version from **filename** (e.g., `plugin-name-1.0.so`)
3. Creates a `LoadedPlugin` struct
4. **Never calls `dlopen` or links the code**

```rust
// loader.rs line 86-112
pub fn load(&mut self, path: &Path) -> Result<PluginMetadata, PluginLoadError> {
    // 1. Verify path exists
    // 2. Parse metadata from FILENAME (not file content!)
    // 3. Validate version format
    // 4. Register LoadedPlugin
    // ❌ NO DYNAMIC LOADING
}
```

**This is a SIGNIFICANT GAP.** The plugin loader is essentially a **registry stub** — it tracks what plugins *should* exist but doesn't actually load their code. Downstream crates must implement their own dynamic loading (using `libloading` or similar).

---

## 3. Compose/Orchestration Engine Analysis

### 3.1 Compose Module (`compose.rs`, 819 lines)

**Status:** ⚠️ **DATA STRUCTURES ONLY — NO EXECUTION ENGINE**

**What's Implemented (Types):**
- `ComposeTemplate` — multi-step template definition
- `ComposeStep` — individual step with condition, dependencies, parallel flag
- `StepAction` enum — Http, Dns, Tcp, Yara, Sigma, Include, Chain
- `ComposeContext` — tracks step results and variables
- `StepResult` — output from a completed step

**What's NOT Implemented (Execution):**
- ❌ No HTTP executor for `HttpStepConfig`
- ❌ No DNS resolver for `DnsStepConfig`
- ❌ No TCP connector for `TcpStepConfig`
- ❌ No YARA integration for `YaraStepConfig`
- ❌ No Sigma integration for `SigmaStepConfig`
- ❌ No template loader for `IncludeStepConfig`
- ❌ No chain rule engine for `ChainStepConfig`

### 3.2 ComposeContext — Partial Implementation

**Implemented:**
- `dependencies_met()` — checks if all dependency steps completed
- `complete_step()` — registers step results and merges variables

**Partially Implemented:**
- `condition_met()` — **EXTREMELY LIMITED** condition evaluation:
  - ✅ `step_name.matched` — checks if step produced matches
  - ✅ `variable != ''` — checks non-empty variable
  - ✅ `variable == 'value'` — exact string match
  - ❌ No comparison operators (`<`, `>`, `<=`, `>=`)
  - ❌ No arithmetic operations
  - ❌ No boolean operators (`&&`, `||`)
  - ❌ No version comparison (e.g., `version < '6.0'`)
  - ❌ No function calls

```rust
// compose.rs line 278-301
pub fn condition_met(&self, step: &ComposeStep) -> bool {
    // Only handles 3 patterns:
    // 1. "step_name.matched"
    // 2. "var != ''"
    // 3. "var == 'value'"
    // Everything else returns FALSE (fail-closed)
}
```

**Tests explicitly document this gap:**
```rust
#[test]
fn version_comparison_in_if_condition() {
    // Current implementation doesn't support version comparison operators
    // This test documents the gap
    let result = ctx.condition_met(&step);
    assert!(!result, "unsupported operators should fail closed");
}
```

### 3.3 Orchestration Gaps

**Missing Critical Features:**
1. **Circular dependency detection** — No DAG validation (test exists documenting gap)
2. **Parallel step scheduling** — `parallel: true` flag exists but no scheduler
3. **Variable conflict resolution** — "Last write wins" is undefined behavior for parallel steps
4. **Step timeout handling** — No timeout mechanism
5. **Error propagation** — No `Result` type for step execution

---

## 4. Matcher System Analysis

### 4.1 Matcher Definitions (`template/matchers.rs`, 143 lines)

**Status:** ✅ **COMPLETE TYPE DEFINITIONS**

**6 MatcherKind Variants:**
- `Word` — Case-insensitive substring (fast path Aho-Corasick)
- `Regex` — Regular expression match
- `Status` — HTTP status code match
- `Size` — Response body size match
- `Binary` — Binary content match (hex encoded)
- `Dsl` — Nuclei expression language

**5 ExtractorKind Variants:**
- `Regex` — Pattern extraction
- `Kval` — Key-value extraction
- `Json` — JSON path extraction
- `Xpath` — XPath extraction
- `Dsl` — DSL expression extraction

### 4.2 MatchDatabase Trait (`matcher.rs`, 280 lines)

**Status:** ⚠️ **TRAIT ONLY — NO IMPLEMENTATION**

```rust
pub trait MatchDatabase: Send + Sync {
    fn scan(&self, response: &ResponseData) -> Vec<Match>;
    fn pattern_count(&self) -> usize;
    fn template_count(&self) -> usize;
}
```

**CRITICAL GAP:** The `MatchDatabase` trait is the advertised crown jewel for "fused pattern matching" — scanning N templates with 1 pass. **There is NO implementation in this crate.**

The README claims:
> "N templates = 1 scan, not N sequential scans"

But secir provides only:
- The `MatchDatabase` trait definition
- `ResponseData` helper for response parsing
- `select_response_part()` helper for part selection

**Actual matching logic must be implemented by downstream crates.** This includes:
- Aho-Corasick automaton construction
- Regex compilation and execution
- Status code comparison
- Size validation
- Binary hex decoding and matching
- DSL expression evaluation

### 4.3 ResponseData (`matcher.rs`)

**Status:** ✅ **WELL-IMPLEMENTED**

`ResponseData` is a solid helper struct:
- Lazy initialization of combined headers+body buffer (`OnceLock`)
- UTF-8 text with lossy fallback for binary content
- Case-insensitive header index
- Named header access

```rust
pub struct ResponseData {
    pub status: u16,
    pub headers: Vec<u8>,
    pub header_map: Vec<(String, String)>,
    pub header_index: HashMap<String, usize>,
    pub body: Vec<u8>,
    pub all: OnceLock<Vec<u8>>,        // Lazy combined
    pub body_text: OnceLock<Box<str>>, // Lazy UTF-8
    pub all_text: OnceLock<Box<str>>,  // Lazy UTF-8
    pub url: Option<String>,
    pub content_length: usize,
    pub elapsed: Duration,
}
```

---

## 5. Types That Exist But Don't Do Anything

### 5.1 Stub-Only Types (Declared, Never Processed)

| Type | Location | Issue |
|------|----------|-------|
| `Template.extends` | `template/mod.rs:282` | No inheritance resolution |
| `Template.flow` | `template/mod.rs:317` | No flow expression parser |
| `Template.parallel_groups` | `template/mod.rs:329` | No parallel execution semantics |
| `RequestDef.condition` | `template/request.rs:177` | No DSL evaluation for request skipping |
| `RequestDef.iterate` | `template/request.rs:181` | No iteration logic |
| `RequestDef.transforms` | `template/request.rs:185` | No transform pipeline |
| `RequestDef.label/goto` | `template/request.rs:189,193` | No control flow |
| `RequestDef.headless_actions` | `template/request.rs:197` | Empty `Vec<serde_json::Value>` |
| `HttpRequestDef.differential` | `template/request.rs:79` | No diff scanning logic |
| `MatcherKind::Dsl` | `template/matchers.rs:73` | No DSL evaluator |
| `ExtractorKind::Dsl` | `template/matchers.rs:134` | No DSL evaluator |
| `Transform` enum | `template/request.rs:505-521` | No transform implementations |
| `Workflow`/`WorkflowStep` | `template/mod.rs:333-348` | No workflow executor |
| `YaraStepConfig` | `compose.rs:185-191` | No YARA integration |
| `SigmaStepConfig` | `compose.rs:193-200` | No Sigma integration |
| `ChainStepConfig`/`ChainAction` | `compose.rs:216-235` | No chain rule engine |
| `StepAction::Include` | `compose.rs:137` | No template inclusion logic |

### 5.2 Transport Traits (`transport.rs`, 167 lines)

**Status:** ⚠️ **TRAIT ONLY — NO IMPLEMENTATIONS**

```rust
pub trait Transport: Send + Sync {
    fn concurrency_limit(&self) -> usize { 1 }
    fn execute(&self, plan: &RequestPlan) -> Pin<Box<dyn Stream<Item = Result<Response>> + Send + '_>>;
}

pub trait Planner: Send + Sync {
    fn plan(&self, targets: &[TargetUrl], templates: &[Template]) -> RequestPlan;
    fn plan_step(&self, targets: &[TargetUrl], templates: &[Template], request_index: usize, contexts: &[TemplateContext]) -> RequestPlan;
}
```

**No implementations provided.** Downstream must implement:
- HTTP client (reqwest, hyper, io_uring)
- Request deduplication logic
- Target expansion
- Template-to-request mapping

---

## 6. Missing Components for a Universal Security IR

### 6.1 Critical Missing Types

| Component | Why Needed | Priority |
|-----------|------------|----------|
| `VariableResolver` | `{{BaseURL}}`, `{{Hostname}}` interpolation | CRITICAL |
| `RequestBuilder` | Convert `RequestDef` to HTTP request | CRITICAL |
| `MatcherEngine` | Actually execute matchers against responses | CRITICAL |
| `ExtractorEngine` | Actually execute extractors | CRITICAL |
| `DslEvaluator` | Nuclei DSL expressions (`contains()`, `regex()`, etc.) | HIGH |
| `TemplateLoader` | Load and parse YAML/TOML templates | HIGH |
| `WorkflowEngine` | Execute multi-step workflows | HIGH |
| `FingerprintDB` | Match extracted versions to known CVEs | MEDIUM |
| `EvidenceCollector` | Capture request/response for findings | MEDIUM |
| `RateLimitEnforcer` | Actually enforce rate limits | MEDIUM |
| `ProgressReporter` | Scan progress callbacks | LOW |

### 6.2 Protocol Request Gaps

The `ProtocolRequest` enum has **protocol-specific request structs**, but they lack:
- Request-to-bytes conversion
- Response parsing
- Protocol-specific matcher logic

Example: `DnsRequestDef` has no way to:
1. Build a DNS query packet
2. Send it to a resolver
3. Parse the DNS response
4. Match against `name`, `query_type`, etc.

### 6.3 Error Handling Gaps

`Error` enum in `error.rs` covers basic cases but misses:
- Matcher compilation errors (invalid regex)
- Extractor failures (invalid JSON path)
- Protocol-specific errors (TCP timeout, DNS NXDOMAIN)
- Workflow errors (circular dependencies, missing steps)

---

## 7. Documentation Gaps

The crate has **#![warn(missing_docs)]** enabled and produces **204 warnings**:

- `patterns` module: Completely undocumented (module, types, variants, fields)
- `compose` module: 24 undocumented struct fields
- `error` module: All struct variant fields undocumented
- `template` submodules: Public re-exports undocumented
- `plugin` submodules: `registry` and `traits` re-exports undocumented
- `plugin::traits`: All `PluginCapability` variant fields undocumented

This is embarrassing for a foundational crate that "everything depends on."

---

## 8. Test Coverage Analysis

**48 tests pass** — good coverage for what's implemented:

| Module | Tests | Coverage |
|--------|-------|----------|
| `template` | 11 | Serialization, defaults, enums |
| `compose` | 11 | Context, dependencies, conditions |
| `plugin/loader` | 5 | Registry operations |
| `plugin/registry` | 5 | Trait registrations |
| `finding` | 3 | Serialization, classification |
| `matcher` | 4 | ResponseData, part selection |
| `error` | 1 | Error codes |
| `error_catalog` | 1 | Catalog uniqueness |
| `transport` | 2 | Basic struct tests |

**Gaps:**
- No integration tests for full template → finding flow
- No property-based tests for serialization
- No fuzzing tests for pattern matching
- No benchmarks (critical for claimed performance advantages)

---

## 9. Summary Table

| Feature | Status | Notes |
|---------|--------|-------|
| Template types | ✅ Complete | Full Nuclei-compatible IR |
| Finding types | ✅ Complete | Rich evidence structure |
| Severity enum | ✅ Complete | CVSS-aligned |
| Plugin traits | ✅ Complete | 12 extensible traits |
| Plugin registry | ✅ Complete | FxHashMap-based lookup |
| Plugin loader | ⚠️ Stub | No dynamic library loading |
| MatchDatabase trait | ⚠️ Interface only | No implementation |
| Matcher types | ✅ Complete | 6 matcher kinds defined |
| Extractor types | ✅ Complete | 5 extractor kinds defined |
| ResponseData | ✅ Complete | Lazy initialization |
| Compose types | ⚠️ Types only | No execution engine |
| Condition evaluation | ⚠️ Partial | 3 simple patterns only |
| Transport traits | ⚠️ Interface only | No implementations |
| Pattern database | ✅ Complete | Embedded TOML defaults |
| Error catalog | ✅ Complete | 9 stable error codes |

---

## 10. Recommendations

### Immediate (High Priority)

1. **Document everything** — 204 doc warnings is unacceptable for a foundational crate
2. **Implement `VariableResolver`** — Template variables can't stay as strings forever
3. **Add matcher engine** — At least a simple word matcher implementation
4. **Fix plugin loader** — Actually load `.so`/`.dll` files using `libloading`

### Short-term (Medium Priority)

5. **Implement DSL evaluator** — `MatcherKind::Dsl` is dead code without it
6. **Add workflow executor** — `Workflow`/`ComposeStep` need runtime
7. **Implement request builders** — Each protocol needs request serialization
8. **Add circular dependency detection** — DAG validation before execution

### Long-term (Lower Priority)

9. **Add benchmarks** — Prove the "fused matching" performance claims
10. **Implement YARA/Sigma bridges** — Complete the compose engine
11. **Add fingerprint database** — Map extracted versions to CVEs
12. **Add progress reporting** — Hook for scan progress

---

## Conclusion

secir is a **solid foundation** with **ambitious architecture** but **incomplete implementation**. It correctly defines the IR boundary between frontends and backends, but the README oversells capabilities. The plugin system is real (traits + registry), but the loader is a stub. The compose engine has great types but no execution. The matcher system has definitions but no engine.

**For a universal security IR:** This is a **good start**, but it's only 40% of what's needed. Downstream crates (the actual scanner implementations) must provide the remaining 60%: matching engines, protocol handlers, DSL evaluators, workflow executors, and plugin loading.

**Grade: B+ for architecture, C for completeness**

The types won't let you build something broken — they'll just prevent you from building something complete without significant additional work.
