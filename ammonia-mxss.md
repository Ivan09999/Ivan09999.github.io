---
layout: default
title: "One Root Cause, Three RCE Sinks"
---

## 3 RCEs, One Root Cause: Auditing ReadMe's Server-Side MDX Pipeline

How an arithmetic probe uncovered three independently reachable server-side RCE sinks sharing one root cause.

*Note: The vulnerable behavior described in this article has since been remediated by the vendor. Public disclosure was authorized by ReadMe. The discussion focuses on the investigation methodology, root cause analysis, and lessons learned.*

**Reading time: 12 minutes**

**Date:** June 2026  
**Severity:** Critical · CVSS 3.1: 9.9 `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`  
**Bounty:** $3,000  
**CWE:** CWE-94 (Code Injection) → CWE-78 (OS Command Injection)

---

### Introduction

While investigating ReadMe's documentation rendering pipeline, I discovered that several independent rendering surfaces evaluated MDX expressions server-side. The first finding looked like a single endpoint issue. It was not. A broader review of the architecture revealed three independently reachable rendering sinks that all shared the same unsandboxed server-side MDX evaluation pipeline.

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

<figure style="text-align:center; margin:2rem 0; overflow:hidden; max-width:100%;">
  <svg viewBox="0 0 500 370" xmlns="http://www.w3.org/2000/svg" style="max-width: 100%; width: 420px; height: auto; display: block; margin: 0 auto 1rem auto;">
    <rect x="150" y="10" width="200" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="250" y="33" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="13">Content</text>

    <line x1="250" y1="46" x2="250" y2="66" stroke="#00ff41" stroke-width="1.5"/>
    <polygon points="250,72 246,66 254,66" fill="#00ff41"/>

    <rect x="150" y="72" width="200" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="250" y="95" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="13">Storage</text>

    <line x1="250" y1="108" x2="250" y2="128" stroke="#00ff41" stroke-width="1.5"/>
    <polygon points="250,134 246,128 254,128" fill="#00ff41"/>

    <rect x="150" y="134" width="200" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="250" y="150" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="13"><tspan x="250">Render Route</tspan><tspan x="250" dy="15">/docs /custom_blocks /page</tspan></text>

    <line x1="250" y1="170" x2="250" y2="190" stroke="#00ff41" stroke-width="1.5"/>
    <polygon points="250,196 246,190 254,190" fill="#00ff41"/>

    <rect x="150" y="196" width="200" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="250" y="212" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="13"><tspan x="250">SSR Layer</tspan><tspan x="250" dy="15">(server-side MDX processing)</tspan></text>

    <line x1="250" y1="232" x2="250" y2="252" stroke="#00ff41" stroke-width="1.5"/>
    <polygon points="250,258 246,252 254,252" fill="#00ff41"/>

    <rect x="150" y="258" width="200" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="250" y="281" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="13">Expression Evaluation</text>

    <line x1="250" y1="294" x2="250" y2="314" stroke="#00ff41" stroke-width="1.5"/>
    <polygon points="250,320 246,314 254,314" fill="#00ff41"/>

    <rect x="150" y="320" width="200" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="250" y="343" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="13">HTML Output</text>
  </svg>
  <figcaption style="font-size: 0.9rem; color: #888; font-style: italic;">
    Figure 1. The rendering pipeline. Content flows through storage and render routes into a shared SSR layer where expressions are evaluated server-side.
  </figcaption>
</figure>

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

The response contained `49`, confirming that the expression had been evaluated on the server before the HTML was returned. That confirmed server-side evaluation on this route.

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

The critical chain was:

**`process` → `process.binding()` → `spawn_sync` → OS command execution**

`process.binding` is the legacy internal API that Node modules use to reach native code. It is deprecated and hidden behind `--no-deprecation` in most contexts, but it is still present in production Node builds. `process.binding('spawn_sync')` returns the internal binding used by `child_process.spawnSync`. Calling it directly bypasses the `child_process` module entirely.

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

<figure style="text-align:center; margin:2rem 0; overflow:hidden; max-width:100%;">
  <svg viewBox="0 0 500 400" xmlns="http://www.w3.org/2000/svg" style="max-width: 100%; width: 350px; height: auto; display: block; margin: 0 auto 1rem auto;">
    <rect x="150" y="10" width="200" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="250" y="33" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="13">Author uploads MDX</text>

    <line x1="250" y1="46" x2="250" y2="66" stroke="#00ff41" stroke-width="1.5"/>
    <polygon points="250,72 246,66 254,66" fill="#00ff41"/>

    <rect x="150" y="72" width="200" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="250" y="88" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="13"><tspan x="250">Server evaluates</tspan><tspan x="250" dy="15">{7*7} → 49</tspan></text>

    <line x1="250" y1="108" x2="250" y2="128" stroke="#00ff41" stroke-width="1.5"/>
    <polygon points="250,134 246,128 254,128" fill="#00ff41"/>

    <rect x="150" y="134" width="200" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="250" y="157" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="13">JavaScript Expression</text>

    <line x1="250" y1="170" x2="250" y2="190" stroke="#00ff41" stroke-width="1.5"/>
    <polygon points="250,196 246,190 254,190" fill="#00ff41"/>

    <rect x="150" y="196" width="200" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="250" y="219" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="13">process.binding()</text>

    <line x1="250" y1="232" x2="250" y2="252" stroke="#ff3333" stroke-width="1.5"/>
    <polygon points="250,258 246,252 254,252" fill="#ff3333"/>

    <rect x="150" y="258" width="200" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="250" y="281" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="13">spawn_sync</text>

    <line x1="250" y1="294" x2="250" y2="314" stroke="#ff3333" stroke-width="1.5"/>
    <polygon points="250,320 246,314 254,314" fill="#ff3333"/>

    <rect x="150" y="320" width="200" height="36" rx="4" fill="#1a0a0a" stroke="#ff3333" stroke-width="1"/>
    <text x="250" y="343" text-anchor="middle" fill="#ff3333" font-family="JetBrains Mono, monospace" font-size="13" font-weight="600">OS Command Execution</text>
  </svg>
  <figcaption style="font-size: 0.9rem; color: #888; font-style: italic;">
    Figure 2. The attack chain. An arithmetic probe escalates through the Node.js scope to OS command execution via process.binding.
  </figcaption>
</figure>

---

### Finding Additional Sinks

Once the root cause was clear, the investigation shifted. The question stopped being "which endpoint is vulnerable" and became "which rendering surfaces share this evaluation logic."

The mental model was simple. Any route that takes stored MDX content, passes it through the shared SSR layer, and returns rendered HTML is a candidate. The endpoint does not matter. The evaluation path matters.

<figure style="text-align:center; margin:2rem 0; overflow:hidden; max-width:100%;">
  <svg viewBox="0 0 500 220" xmlns="http://www.w3.org/2000/svg" style="max-width: 100%; width: 450px; height: auto; display: block; margin: 0 auto 1rem auto;">
    <!-- Docs guides -->
    <rect x="20" y="20" width="130" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="85" y="43" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="12">Docs guides</text>
    <line x1="150" y1="38" x2="195" y2="100" stroke="#00ff41" stroke-width="1.5"/>
    <polygon points="195,100 187,96 190,90" fill="#00ff41"/>

    <!-- Custom blocks -->
    <rect x="20" y="92" width="130" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="85" y="115" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="12">Custom blocks</text>
    <line x1="150" y1="110" x2="215" y2="110" stroke="#00ff41" stroke-width="1.5"/>
    <polygon points="215,110 209,106 209,114" fill="#00ff41"/>

    <!-- Custom pages -->
    <rect x="20" y="164" width="130" height="36" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="85" y="187" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="12">Custom pages</text>
    <line x1="150" y1="182" x2="195" y2="120" stroke="#00ff41" stroke-width="1.5"/>
    <polygon points="195,120 190,128 187,122" fill="#00ff41"/>

    <!-- Shared MDX Evaluation Pipeline (red - the bug) -->
    <rect x="215" y="92" width="180" height="36" rx="4" fill="#1a0a0a" stroke="#ff3333" stroke-width="1"/>
    <text x="305" y="108" text-anchor="middle" fill="#ff3333" font-family="JetBrains Mono, monospace" font-size="12"><tspan x="305">Shared MDX Evaluation</tspan><tspan x="305" dy="14">Pipeline (unsandboxed)</tspan></text>

    <!-- Arrow to RCE -->
    <line x1="395" y1="110" x2="450" y2="110" stroke="#ff3333" stroke-width="1.5"/>
    <polygon points="450,110 444,106 444,114" fill="#ff3333"/>
    <text x="470" y="114" text-anchor="middle" fill="#ff3333" font-family="JetBrains Mono, monospace" font-size="12" font-weight="600">RCE</text>
  </svg>
  <figcaption style="font-size: 0.9rem; color: #888; font-style: italic;">
    Figure 3. Three independent content types all funnel through the same shared MDX evaluation pipeline where unsandboxed expression evaluation enables RCE.
  </figcaption>
</figure>

Three content types fit the model:

- **Docs guides** — the primary documentation content type, served at `GET /docs/{slug}`. The body is stored as documentation content.
- **Custom blocks** — reusable MDX components, rendered via `POST /custom_blocks/{name}/render`. The source is stored as MDX content.
- **Custom pages** — standalone pages served at `GET /page/{slug}`. The body is stored as page content.

Each was tested with the same arithmetic probe. Each returned `49`. Each was then tested with the `whoami` payload. Each returned `<service-account>`.

These were not duplicate bugs. They were independent routes with independent storage, each reaching the same shared evaluator. Addressing only a single rendering surface would leave the remaining routes unaffected if they continued to share the same evaluation behavior. The architecture, not any single route, was the vulnerability.

This is the methodological takeaway. When a rendering sink is found, the right move is to audit every surface that shares the render path, not to file the first finding and stop. Shared rendering code creates shared vulnerabilities. The bug lives in the shared layer, and every route through that layer is a sink.

---

### Root Cause

The observed behavior strongly suggests that the renderer evaluated MDX expressions in an unsandboxed Node.js context. The behavior was consistent with a renderer configured to evaluate expressions server-side without an effective sandbox.

All three rendering surfaces exhibited identical behavior, suggesting they shared the same evaluation pipeline. There was no evidence of a per-route override. The docs renderer, the custom blocks renderer, and the custom pages renderer all produced the same results from the same payloads, which strongly suggested a common rendering implementation underlying all three.

<figure style="text-align:center; margin:2rem 0; overflow:hidden; max-width:100%;">
  <svg viewBox="0 0 500 200" xmlns="http://www.w3.org/2000/svg" style="max-width: 100%; width: 500px; height: auto; display: block; margin: 0 auto 1rem auto;">
    <!-- Outer box - shared evaluation layer -->
    <rect x="40" y="20" width="420" height="160" rx="6" fill="#1a0a0a" stroke="#ff3333" stroke-width="1.5"/>
    <text x="250" y="45" text-anchor="middle" fill="#ff3333" font-family="JetBrains Mono, monospace" font-size="13" font-weight="600">Shared MDX Evaluation Layer</text>
    <text x="250" y="62" text-anchor="middle" fill="#888" font-family="JetBrains Mono, monospace" font-size="11">server-side expression evaluation, no effective sandbox</text>
    <text x="250" y="78" text-anchor="middle" fill="#ff3333" font-family="JetBrains Mono, monospace" font-size="10">◀── root cause</text>

    <!-- Three inner renderer boxes -->
    <rect x="70" y="100" width="110" height="50" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="125" y="120" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="11"><tspan x="125">Docs</tspan><tspan x="125" dy="14">renderer</tspan></text>

    <rect x="195" y="100" width="110" height="50" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="250" y="120" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="11"><tspan x="250">Custom blocks</tspan><tspan x="250" dy="14">renderer</tspan></text>

    <rect x="320" y="100" width="110" height="50" rx="4" fill="#111" stroke="#2a2a2a" stroke-width="1"/>
    <text x="375" y="120" text-anchor="middle" fill="#d0d0d0" font-family="JetBrains Mono, monospace" font-size="11"><tspan x="375">Custom pages</tspan><tspan x="375" dy="14">renderer</tspan></text>
  </svg>
  <figcaption style="font-size: 0.9rem; color: #888; font-style: italic;">
    Figure 4. The root cause. All three renderers inherit the same unsafe evaluation layer. Fixing one route does not fix the architecture.
  </figcaption>
</figure>

This is a common architectural pattern, and a common failure mode. A rendering service centralizes its MDX handling to avoid duplication. That centralization is good engineering. But if the centralized behavior is unsafe, every consumer inherits the risk. The fix is not to patch routes. The fix is to fix the evaluation behavior at the shared layer.

---

### Why This Became RCE

The escalation from expression evaluation to RCE depended on three things being true at once.

**`process` was in scope.** `require` and `module` were unavailable, but `process` was present. This is the gap that made everything else possible. `process` is a Node global attached to `globalThis`. Scope filtering that targets module-system objects does not necessarily remove it.

**`process.binding` was reachable.** `process.binding` is the internal API that Node's own modules use to access native code. It is deprecated and discouraged, but it is present in production Node. It is not removed by filtering `require`, because it is not accessed through the module system. `process.binding('spawn_sync')` returns the native binding behind `child_process.spawnSync`.

**No string or keyword filter was applied.** The payload contained literal strings like `spawn_sync`, `/bin/sh`, and `whoami`. None were blocked. A keyword-based filter might have detected these strings. The absence of any filter meant the trivial payload worked directly.

These three conditions compound. Removing any one of them would have stopped the trivial exploit. `process` out of scope closes the binding path. `process.binding` removed closes the native spawn path. A keyword filter on `spawn_sync` forces the attacker into obfuscation, which is harder but not impossible. One missing layer of defense was enough to enable full RCE.

---


### Patch Recommendations

The fix belongs at the shared layer, not at individual routes.

**Disable server-side expression evaluation.** If expressions do not need to run on the server, the safest option is to not evaluate them there. If server-side evaluation is unnecessary, treating `{ ... }` as literal text eliminates the attack surface entirely.

**Sandbox evaluation if it must run.** If server-side evaluation is a product requirement, it must run in a hardened JavaScript sandbox. `isolated-vm` provides a separate V8 isolate with its own heap and no access to the host process. At minimum, the evaluation scope should not expose `process`, `process.binding`, `globalThis`, or the `Function` constructor. The sandbox must be applied at the shared evaluation layer so every route inherits it.

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

### Conclusion

What initially appeared to be a single server-side code execution bug ultimately turned out to be an architectural issue affecting multiple rendering surfaces.

Rather than treating the first vulnerable endpoint as an isolated finding, following the shared rendering pipeline uncovered three independently reachable RCE sinks originating from the same underlying evaluation behavior.

For security researchers, the lesson is straightforward: when a rendering sink is discovered, understanding the application's architecture is often more valuable than continued endpoint fuzzing. Shared execution paths frequently create shared vulnerabilities, and fixing the architecture - not individual routes - is what ultimately eliminates the risk.

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
