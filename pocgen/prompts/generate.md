You are generating a minimal, safe JavaScript PoC for a jsflow finding.

Use the compact agent packet as the primary task contract. Treat the evidence
section as optional supporting material. Do not inspect the full report unless
the packet and provided evidence are insufficient.

## Agent Packet

```json
{agent_packet}
```

## Evidence Pointer

- report: `{evidence_uri}`
- finding path: `{evidence_path}`

## Staged Evidence

```json
{evidence}
```

## Output Directory

Write all artifacts under:

```text
{output_dir}
```

## Target Package Root

The vulnerable package root is:

```text
{target_cwd}
```

Important: generated PoC files are stored in the output directory, so relative
JavaScript imports such as `require('./index.js')` resolve relative to the PoC
file, not the target package root. When the packet gives a relative
`require_path`, resolve it from the target package root and use an absolute path
or a correct relative path from the generated PoC file.

## Requirements

1. Create the smallest runnable PoC artifact, usually `poc.js`, `poc.cjs`, or
   `poc.mjs`.
2. Prefer mocking dangerous sinks instead of executing real side effects.
3. Use the payload candidate from the packet when it is present.
4. Assert the preferred validation oracle.
5. Print `PASS` only when the oracle fires.
6. Create or update `README-PoC.md` with:
   - finding summary
   - artifacts
   - exact run command
   - expected success signal
   - observed validation status if known
   - remaining uncertainty

Keep the harness direct. Do not start an HTTP server or install dependencies if
a direct function call and mock sink can reach the vulnerable path.
