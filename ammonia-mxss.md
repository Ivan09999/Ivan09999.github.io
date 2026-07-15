---
layout: default
title: "mXSS in ammonia"
---

## Finding mXSS in a Rust HTML Sanitizer

**Date:** June 2026  
**Program:** ammonia (Rust HTML sanitizer, crates.io)  
**Severity:** Moderate  
**Status:** [Published — GHSA-9jh8-v38h-cvhr](https://github.com/rust-ammonia/ammonia/security/advisories/GHSA-9jh8-v38h-cvhr)  
**CVE:** Requested

---

### Introduction

In June 2026, I found a mutation XSS in `ammonia`, a Rust HTML sanitizer with millions of downloads. The bug was a distinct root cause from the previous advisory (GHSA-mm7x-qfjj-5g2c, patched in 4.1.2). That patch added namespace validation for MathML and SVG integration points, but it missed one edge case: `annotation-xml`, whose integration-point status is **conditional on an attribute value** rather than intrinsic to the element.

This post explains how stripping a single harmless-looking attribute — `encoding` — can flip a browser's parsing context and turn a safe-looking sanitizer output into a live XSS payload.

---

### What is ammonia?

`ammonia` is a whitelist-based HTML sanitizer for Rust. It parses untrusted HTML, strips dangerous tags and attributes, and serializes clean HTML back to a string. It's used by forums, chat apps, and documentation platforms to display user-generated content safely.

The core promise: what goes in as untrusted HTML comes out as safe HTML.

---

### The Bug

MathML has a concept called **integration points** — elements that temporarily switch the parser from MathML mode back to HTML mode. One of these is `<annotation-xml>`, but **only when it carries `encoding="text/html"`**.

`ammonia` correctly strips the `encoding` attribute (it's not in the default allowlist). But it validates namespace compatibility **on the parsed DOM before the attribute filter executes**. This means:

1. **First parse:** `encoding="text/html"` is present → `<annotation-xml>` is treated as an integration point → `<style>` inside it stays as raw HTML text.
2. **Sanitizer strips `encoding`** → output no longer has the attribute.
3. **Browser re-parses the output:** `encoding` is gone → `<annotation-xml>` is *not* an integration point → `<style>` is now parsed in MathML context, where its content is **not** treated as raw text. The HTML comment `<!--` that was hiding the `<img onerror>` payload is no longer valid, and the content re-parses as live HTML, escaping the `<math>` container entirely.

The result: a stored XSS that bypasses the sanitizer.

---

### Reproduction

Confirmed on `ammonia = "4.1.2"`:

```rust
use ammonia::Builder;
use std::collections::{HashMap, HashSet};

fn main() {
    let mut b = Builder::default();
    b.add_tags(&["math", "annotation-xml", "style", "img"]);

    let mut img = HashSet::new();
    img.insert("title");
    img.insert("src");

    let mut attrs: HashMap<&str, HashSet<&str>> = HashMap::new();
    attrs.insert("img", img);
    b.tag_attributes(attrs);

    let input = r#"<math><annotation-xml encoding="text/html"><style><!--</style><img title="--!&gt;&lt;img src=1 onerror=alert(1)&gt;"></annotation-xml></math>"#;
    
    println!("{}", b.clean(input));
}
Sanitizer output:
HTML
<math><annotation-xml><style><!--</style><img title="--!><img src=1 onerror=alert(1)>"></annotation-xml></math>
When a browser re-parses this, alert(1) fires. The <img onerror> escapes the <math> container entirely and lands in the HTML namespace.
Control test: If you add encoding to the annotation-xml attribute allowlist so it survives sanitization, the alert does not fire. The single missing attribute is the entire difference between safe and exploited. This confirms the root cause is the integration-point status flip, not a generic parser bypass.
Root Cause
The fix added in 4.1.2 lives in check_expected_namespace (around line 2068):
rust
} else if parent.ns == ns!(mathml) && child.ns != ns!(mathml) {
    matches!(&*parent.local,
        "mi" | "mo" | "mn" | "ms" | "mtext" | "annotation-xml")
    && if child.ns == ns!(html) { is_html_tag(&child.local) } else { true }
}
Every other element in that list is an unconditional integration point. annotation-xml is the only one whose status depends on an attribute value (encoding="text/html"). The function never checks encoding, and by the time it runs, the attribute filter has already stripped it.
Namespace validation runs on the parsed DOM before the attribute filter executes, so by the time encoding is stripped, the namespace check has already passed based on the attribute's presence. The sanitizer serializes a DOM it believes is safe, but the browser re-parses it under different rules.
A grep for encoding in src/lib.rs shows it only appears in doc comments — nowhere in the validation logic.
Why This Wasn't a Duplicate
The previous advisory (GHSA-mm7x-qfjj-5g2c) was patched in 4.1.2 — the exact version I tested on. That patch added check_expected_namespace and regression tests for mtext (MathML) and foreignObject (SVG), both of which are unconditional integration points. annotation-xml, whose status depends on the encoding attribute, was not covered by those tests.
Same attack pattern — sanitize-parse vs. browser re-parse mismatch with a raw-text HTML element as the gadget — but a different root cause: the gap was inside the new validation function, not the absence of the function itself.
Impact
Stored XSS in the page origin. In the typical use case — sanitizing user content for display to other users — this allows session cookie theft and same-origin actions on behalf of any viewer.
Severity is Moderate because it requires a non-default config: the application must explicitly allow math + annotation-xml + at least one raw-text HTML element (e.g. style, noscript, iframe). A default ammonia config is not vulnerable.
Disclosure Timeline
Table
Date	Event
2026-06-29	Reported to maintainer
2026-07-01	Maintainer approved disclosure
2026-07-15	Advisory published (GHSA-9jh8-v38h-cvhr)
Pending	CVE assignment
