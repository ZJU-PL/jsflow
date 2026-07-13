# pocgen

`pocgen` is the automated PoC-generation runner for probejs reports.

It is separate from `skills/probejs-poc-generation/`:

- the skill is the interactive/manual workflow,
- `pocgen` is the reproducible Python runner that can call CLI coding agents,
  validate artifacts, retry with staged evidence, and save run logs.

## Basic Usage

```bash
python pocgen/generate.py \
  --report logs/<timestamp>/report.json \
  --finding 0 \
  --agent codex \
  --model default \
  --output evaluation/pocs/<case-id>/
```

`--model` is passed directly to the Claude backend. For Codex and OpenCode,
model flags vary by CLI version; pass backend-specific flags with repeatable
`--agent-arg` options when needed. Each `--agent-arg` is one argv token; for
Codex and OpenCode these extra args are inserted before the generated prompt:

```bash
python pocgen/generate.py \
  --report logs/<timestamp>/report.json \
  --finding 0 \
  --agent codex \
  --agent-arg=--model \
  --agent-arg gpt-5.3-codex \
  --output evaluation/pocs/<case-id>/
```

For a dry run that writes the compact packet and prompts without calling an
agent:

```bash
python pocgen/generate.py \
  --report logs/<timestamp>/report.json \
  --finding 0 \
  --output /tmp/probejs-pocgen-case \
  --dry-run
```

By default, validation runs the first generated `poc.js`, `poc.cjs`, or
`poc.mjs`. If the agent edits one of the copied templates instead, `pocgen`
will run the modified template. To pin an exact command, pass:

```bash
python pocgen/generate.py \
  --report logs/<timestamp>/report.json \
  --finding 0 \
  --output evaluation/pocs/<case-id>/ \
  --validation-command "node poc.cjs"
```

The validation command is executed from the output directory.

## Evidence Policy

The first generation attempt uses only `finding.poc.agent_packet`. If validation
fails, later attempts add evidence in stages:

1. `finding.poc.thin_slice`, `payload_contract`, and `validation_oracle`
2. `trace`, `path`, `rule_evaluation`, and exploit candidates
3. full finding

The goal is to avoid dumping the entire `report.json` into the agent context by
default.

## Outputs

The output directory contains:

- `agent_packet.json`
- `finding_poc.json`
- `prompt-stage-<n>.md`
- `agent-result-stage-<n>.json` when an agent is run
- generated PoC artifacts
- `pocgen-result.json`

`pocgen-result.json` records status, attempts, validation output, target cwd,
and artifact paths.
