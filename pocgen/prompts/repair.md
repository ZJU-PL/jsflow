You are repairing a generated JavaScript PoC for a jsflow finding.

The previous attempt did not validate. Use the compact packet first, then the
new staged evidence if it explains the failure. Keep the PoC minimal and safe.

## Agent Packet

```json
{agent_packet}
```

## Evidence Pointer

- report: `{evidence_uri}`
- finding path: `{evidence_path}`

## New Staged Evidence

```json
{evidence}
```

## Previous Validation Result

```json
{validation}
```

## Output Directory

Modify artifacts under:

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

## Repair Requirements

1. Inspect the current PoC artifact and validation failure.
2. Fix import path, call shape, payload placement, mock timing, or async behavior.
3. Add no unnecessary framework bootstrapping.
4. Keep dangerous sinks mocked when possible.
5. Print `PASS` only when the oracle fires.
6. Update `README-PoC.md` with the real validation status and remaining uncertainty.
