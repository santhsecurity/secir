# secir

Security Intermediate Representation. A shared type vocabulary for security scanning tools. Defines templates, findings, matchers, severities, and transport abstractions so frontends and backends can communicate without hardcoding tool-specific formats.

```rust
use secir::{Template, Finding, Severity, FindingKind, TemplateId};

// Create a finding from a template
let finding = Finding::new(
    TemplateId::from("CVE-2021-44228"),
    "Log4j RCE".to_string(),
    "https://example.com".to_string(),
    Severity::Critical,
    "https://example.com/api".to_string(),
);

// Serialize to JSON for reporting
let json = serde_json::to_string(&finding).unwrap();
```

## Why this exists

Every security scanner reinvents the same types. Templates that define what to probe. Matchers that evaluate responses. Findings that report results. Protocol handlers for HTTP, DNS, TCP, SSL. Most tools hardcode these against their own YAML format.

secir separates the IR from the implementations. Frontend compilers translate Nuclei YAML, Sigma rules, or custom DSLs into secir types. Backend executors consume secir types to perform actual scanning. Optimization passes deduplicate requests, fuse matchers, and JIT-compile hot paths without touching either frontend or backend code.

## Core types

| Type | Purpose |
|------|---------|
| `Template` | Complete scan specification with requests, matchers, and metadata |
| `Finding` | Confirmed scan result with evidence, severity, and extraction data |
| `Severity` | CVSS-aligned classification: Info, Low, Medium, High, Critical, Unknown |
| `FindingKind` | Classification: Vulnerability, Misconfiguration, Exposure, etc. |
| `MatchDatabase` | Trait for fused pattern matching across all templates |
| `ResponseData` | Structured response with status, headers, body for matchers |
| `Transport` | Trait abstracting HTTP clients (reqwest, hyper, io_uring) |
| `Planner` | Trait for deduplicating requests across templates |

## Protocol coverage

Templates support multiple protocols via `ProtocolRequest`:

- `HttpRequestDef` — HTTP/HTTPS with methods, headers, body
- `DnsRequestDef` — DNS queries
- `TcpRequestDef` — Raw TCP probing
- `SslRequestDef` — SSL/TLS certificate inspection
- `WebsocketRequestDef` — WebSocket communication
- `WhoisRequestDef` — WHOIS lookups
- `FileRequestDef` — Local file-based templates
- `CodeRequestDef` — Code execution templates
- `HeadlessRequestDef` — Browser automation

## Extension traits

The `plugin` module defines traits for extending secir without forking:

- `ProtocolHandler` — Add new scan protocols
- `TemplateCompiler` — Add new template formats
- `CustomMatcher` — Add new matching algorithms
- `CustomExtractor` — Add new data extraction methods
- `CustomTransform` — Add new transform stages
- `CustomReporter` — Add reporting formats and sinks
- `PostProcessor` — Enrich findings after scans
- `TargetDiscovery` — Discover scan targets from external systems
- `Authenticator` — Supply authentication material
- `FindingStore` — Persist findings across runs
- `RateLimiter` — Control host-level throttling
- `ScanScheduler` — Schedule recurring or queued scans

## Response matching

The `MatchDatabase` trait enables fused pattern matching. Instead of scanning N templates sequentially against each response, implementations compile all word, regex, and status matchers into a single automaton. One scan evaluates all patterns simultaneously.

```rust
use secir::{ResponseData, MatchDatabase, Match};

let response = ResponseData::new(
    200,
    vec![("Content-Type".to_string(), "text/html".to_string())],
    body_bytes,
);

let matches: Vec<Match> = database.scan(&response);
```

## Severity classification

`Severity` maps to CVSS levels and serializes to lowercase strings:

```rust
use secir::Severity;

let sev = Severity::High;
assert_eq!(sev.as_str(), "high");
```

## Contributing

Pull requests are welcome. There is no such thing as a perfect crate. If you find a bug, a better API, or just a rough edge, open a PR. We review quickly.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.

[![crates.io](https://img.shields.io/crates/v/secir.svg)](https://crates.io/crates/secir)
[![docs.rs](https://docs.rs/secir/badge.svg)](https://docs.rs/secir)
