---
name: probejs-poc-generation
description: Generate minimal runnable PoCs from probejs findings, raw taint summaries, or vulnerability reports for JavaScript targets.
---

# ProbeJS PoC Generation (Experimental)

> **Disclaimer**: This skill is an **experimental** utility separate from probejs's core static analysis. It consumes `report.json` output but relies on manual inspection and external LLM-based coding agents. Generated PoCs should always be manually validated.

Use this skill when a probejs report needs to be turned into a concrete, minimal PoC.

## Goal

Produce:

- a runnable PoC artifact,
- a clear success oracle,
- exact reproduction steps,
- and an honest validation result.

At minimum, create `README-PoC.md` and one runnable artifact such as `poc.js`, `poc.mjs`, or `http-request.txt`.

## Inputs

Prefer a canonical `probejs` `report.json` finding emitted by `--json`, and treat `finding.poc` as the primary PoC-facing contract.

If the input is a raw probejs output instead, extract the required PoC fields inline as part of the workflow rather than relying on a separate normalization script.

When a `probejs` report already contains `finding.poc`, prefer it over local guesswork. Use `finding.poc_guidance` only as supporting detail when needed. The skill should spend effort on PoC generation and validation, not on re-deriving entrypoints that probejs already recovered.

See:

- `probejs/report.schema.json` for the canonical probejs report contract, including `finding.poc`
- `finding.schema.json` for the PoC-oriented field checklist
- `examples/finding.sample.json` for a PoC-oriented sample
- `examples/raw_probejs_summary.sample.json` for a raw input sample that may require manual field extraction

## Workflow

### 1. Restate the finding

Extract or infer:

- vulnerability type,
- target package root and entry file,
- require/import path,
- entry function or constructor,
- invocation mode,
- attacker-controlled source,
- sink,
- concrete payload candidates,
- success oracle,
- runtime assumptions.

Record every inferred field as an assumption if the report does not state it directly.

### 2. Choose the invocation path in this order

Prefer the first working option:

1. direct exported function or class call
2. existing example or unit-test style call shape from the target repo
3. module initialization on `require()` or `import`
4. CLI entrypoint
5. HTTP route or full app startup

Do not start an HTTP server if a direct library call reaches the same sink.

### 3. Minimize the trigger

Keep only the code needed to hit the sink.

- Avoid framework bootstrapping unless the sink is route-only.
- Use concrete short payloads.
- Stub dependencies only when they block the vulnerable path.
- Preserve async behavior with `await`, callbacks, or event waits as needed.

If the finding has a long trace, derive the smallest triggering slice that still reaches the sink.

### 4. Pick a concrete oracle

Choose a benign, observable post-condition.

- `os_command`: unique stdout token or marker file
- `path_traversal`: attacker-chosen file contents are returned
- `xss`: payload string survives into response body or headers
- `code_exec`: controlled code prints a unique token
- `nosql`: auth bypass or widened query result is observable
- `proto_pollution`: polluted property appears on a fresh object or the intended target
- `int_prop_tampering`: mutated internal property changes behavior or state

Prefer stdout over filesystem side effects when both are possible.

### 5. Generate artifacts

Use the smallest matching template in `templates/`:

- `direct-call.cjs.template`
- `esm-import.mjs.template`
- `module-init.cjs.template`
- `proto-poc.cjs.template`
- `http-request.txt.template`
- `README-PoC.template.md`

Only emit optional files that are actually used by the reproduction.

### 6. Validate

If execution is available, run the PoC and refine it until it either works or has a well-explained blocker.

When validation fails:

- inspect the stack trace or observed output,
- fix import paths, call shape, payload quoting, or async timing,
- rerun,
- update `README-PoC.md` with the real status.

Never label a speculative PoC as validated.

## Vulnerability guidance

### OS command injection

- Prefer `echo PROBEJS_POC_SUCCESS` over destructive commands.
- If separators are filtered, adapt quoting or argument boundaries to the sink context.
- If the sink is `execFile` or `spawn`, verify whether shell parsing is actually involved.

### Path traversal

- Determine whether the sink reads, writes, deletes, or streams.
- Prefer reading a benign file in the repo or a temporary marker file you create.
- Prove the traversal reaches the filesystem primitive, not just path concatenation.

### XSS

- Show the reflection point, not just the HTTP status code.
- Start with a unique marker string before using script tags.
- If templating escapes input, prove whether the sink is still exploitable.

### Code execution

- Check `eval`, `Function`, `vm`, template compilation, and string timers.
- Use a unique console token or controlled return value.

### NoSQL injection

- Match the payload to the actual query shape.
- Prefer a visible auth bypass or broadened result set.
- Do not claim exploitability from a parse error alone.

### Prototype pollution

- Distinguish global prototype pollution from target-object mutation.
- Show the write primitive and the observable post-condition in the same PoC.
- Reset or isolate process state if repeated runs would reuse the polluted prototype.

### Internal property tampering

- Identify the internal property, how user input reaches it, and the behavior change it controls.
- Prefer an oracle that shows authorization bypass, option flipping, or altered dispatch.

## Required output

`README-PoC.md` must include:

1. finding summary
2. normalized assumptions
3. generated artifacts
4. exact run command
5. expected success signal
6. observed output
7. validation result
8. remaining uncertainty
9. cleanup notes

## Do not

- Do not use destructive payloads.
- Do not overbuild the environment.
- Do not hide assumptions.
- Do not omit validation status.
- Do not keep dead scaffolding in the final PoC.
