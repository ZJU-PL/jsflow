# PoC Report

## Finding summary

- **ID**: probejs/os_command/2
- **Type**: os_command
- **Entry file**: index.js
- **Entry function**: default CommonJS export
- **Source**: exported module argument at `index.js:4`
- **Sink**: `child_process.execSync` at `index.js:20`

## Assumptions

- The PoC starts from `logs/20260312_220311/report.json`, not a handwritten finding.
- The module can be imported directly from the unpacked `src/` directory.
- Creating a marker file in `/tmp` is an acceptable benign oracle.

## Generated artifacts

- `finding.json`
- `poc.js`

## How to run

```bash
cd /Users/rainoftime/Work/analysis/probejs/evaluation/skill-trials/report-json-find-exec-1.0.2
node poc.js
```

## Expected success signal

The PoC prints `PROBEJS_POC_SUCCESS` after confirming that `/tmp/probejs_report_skill_marker` was created by the injected command.

## Observed output

```text
PROBEJS_POC_SUCCESS ; touch /tmp/probejs_report_skill_marker
```

## Validation result

- Status: validated
- Notes: The JSON report was sufficient to recover the vulnerable package path, source context, and exploit candidate shape.

## Remaining uncertainty

The normalized report finding still needed a small human refinement: the direct entrypoint is the module export, not the intermediate helper names recovered in the path summary.

## Cleanup notes

The PoC removes the marker file before exiting.
