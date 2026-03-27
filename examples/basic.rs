//! Basic secir usage — build a security scan template.

use secir::{Severity, Template};
use secir::template::request::RequestDef;

fn main() {
    let template = Template::builder("admin-panel-detect")
        .name("Admin Panel Detection")
        .severity(Severity::Medium)
        .tags(vec!["admin".into(), "panel".into()])
        .request(RequestDef::http_get(vec!["/admin".into(), "/wp-admin".into()]))
        .build()
        .expect("template should build");

    println!("Template: {} — {}", template.id, template.info.name);
    println!("Severity: {:?}", template.info.severity);
    println!("Requests: {} paths", template.requests.len());
    println!("Tags: {:?}", template.info.tags);
}
