#![warn(missing_docs)]
//! # secir — Security Intermediate Representation
//!
//! The universal type vocabulary for security scanning tools.
//!
//! Every security scanner needs the same concepts: templates that define
//! what to probe, protocols that specify how to probe, matchers that
//! evaluate responses, and findings that report results. This crate
//! defines those concepts as a shared, tool-agnostic intermediate
//! representation.
//!
//! ## Design Philosophy
//!
//! secir is to security scanning what LLVM IR is to compilers:
//!
//! - **Frontend compilers** translate tool-specific formats (Nuclei YAML,
//!   Sigma rules, YARA rules, custom DSLs) into secir types.
//! - **Backend executors** consume secir types to perform actual scanning
//!   over HTTP, DNS, TCP, SSL, WebSocket, or any other protocol.
//! - **Optimization passes** operate on the IR to deduplicate requests,
//!   fuse matchers, predict responses, and JIT-compile hot paths.
//!
//! ## Core Types
//!
//! - [`Template`] — a complete scan specification (requests + matchers + metadata)
//! - [`Finding`] — a confirmed scan result with evidence
//! - [`Severity`] — CVSS-aligned severity classification
//! - [`Transport`] — request/response transport abstraction
//!
//! ## Extension Points
//!
//! secir is extensible via traits in the [`plugin`] module:
//! - [`plugin::ProtocolHandler`] — adds new scan protocols
//! - [`plugin::TemplateCompiler`] — adds new template formats
//! - [`plugin::CustomMatcher`] — adds new matching algorithms
//! - [`plugin::CustomExtractor`] — adds new data extraction methods
//! - [`plugin::CustomTransform`] — adds new transform stages
//! - [`plugin::CustomReporter`] — adds reporting formats and sinks
//! - [`plugin::PostProcessor`] — enriches findings after scans
//! - [`plugin::TargetDiscovery`] — discovers scan targets from external systems
//! - [`plugin::Authenticator`] — supplies authentication material
//! - [`plugin::FindingStore`] — persists findings across runs
//! - [`plugin::RateLimiter`] — controls host-level throttling
//! - [`plugin::ScanScheduler`] — schedules recurring or queued scans

#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_pass_by_value)]


pub mod compose;
pub mod patterns;
pub mod error;
pub mod error_catalog;
pub mod finding;
pub mod matcher;
pub mod plugin;
pub mod severity;
pub mod template;
pub mod transport;

pub use error::{Error, Result};
pub use error_catalog::{ALL_ERROR_CATALOG, ErrorCatalogEntry, entry_for as error_catalog_entry};
pub use finding::{Finding, FindingKind};
pub use matcher::{Match, MatchDatabase, ResponseData, select_response_part};
pub use severity::Severity;
pub use template::{
    AttackType, CodeRequestDef, DnsRequestDef, Encoding, ExtractorDef, ExtractorKind,
    FileRequestDef, HeadlessRequestDef, HttpRequestDef, IterateConfig, MatchPart, MatcherCondition,
    MatcherDef, MatcherKind, NetworkInput, NetworkInputType, ParallelGroup, Protocol,
    ProtocolRequest, RequestDef, SslRequestDef, TcpRequestDef, Template, TemplateId, TemplateInfo,
    TemplateMeta, Transform, WebsocketRequestDef, WhoisRequestDef, Workflow, WorkflowStep,
};
pub use transport::{RequestPlan, RequestSpec, Response, TargetUrl, Transport};
