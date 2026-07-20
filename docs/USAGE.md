# Usage Guide

## Command Line Interface

### Basic Usage

```bash
# Analyze a JavaScript file
python -m probejs input.js

# Analyze with specific vulnerability type
python -m probejs -t os_command input.js

# Check for prototype pollution
python -m probejs -P input.js

# Module mode (analyze as npm module)
python -m probejs -m input.js

# Exit when vulnerability is found
python -m probejs -q -t xss input.js

# Print logs to console
python -m probejs -p input.js
```

### TypeScript

TypeScript files are detected from their extension and use the same commands as JavaScript:

```bash
python -m probejs src/index.ts
python -m probejs --json -t os_command src/index.ts
python -m probejs ./src
```

Supported source extensions are `.ts`, `.tsx`, `.mts`, `.cts`, and ArkTS `.ets`. Source is compiled to CommonJS, so the downstream graph builder remains the same JavaScript pipeline. The nearest `tsconfig.json` is compiled as a project; project references, `baseUrl`, `paths`, package `exports`/`imports`, and npm/pnpm-style workspaces are resolved. Findings are mapped back to original source positions through source maps.

ArkTS `.ets` handling normalizes the common runtime-relevant subset: `struct` components, standard ArkUI decorators, declarative component blocks, and `@Entry` `build()` bodies. Vendor-only syntax outside that subset should be compiled to CommonJS with the HarmonyOS toolchain first and the emitted JavaScript supplied to probejs.

For TypeScript read from standard input, pass `--typescript` explicitly because stdin has no filename:

```bash
printf 'const input: string = process.argv[2];' | python -m probejs --typescript -
```

Type-only constructs are erased from the analyzed program. Declaration signatures are retained as compact metadata for callback registration and promise-returning APIs, but probejs remains a runtime-oriented flow analysis rather than a TypeScript type checker.

When JSON reporting is enabled, `frontend.compilers` records the selected TypeScript compiler and `frontend.diagnostics` contains structured syntax, configuration, module-resolution, and semantic diagnostics. Diagnostics do not prevent analysis-oriented CommonJS emission. HarmonyOS project manifests discovered for `.ets` inputs are reported under `frontend.arkts_projects`.

### Command Line Options

- `-p, --print`: Print logs to console instead of file
- `-t, --vul-type`: Set vulnerability type (`os_command`, `xss`, `code_exec`, `proto_pollution`, `path_traversal`, `nosql`)
- `-P, --prototype-pollution`: Check for prototype pollution
- `-I, --int-prop-tampering`: Check for internal property tampering
- `-m, --module`: Module mode (treat input as npm module)
- `-q, --exit`: Exit when vulnerability is found
- `-s, --single-branch`: Single branch mode (no path explosion)
- `-a, --run-all`: Run all exported functions
- `-f, --function-timeout`: Time limit for function execution (seconds)
- `-c, --call-limit`: Limit on call statement depth (default: 3)
- `-e, --entry-func`: Specify entry function name
- `-F, --nfb, --no-file-based`: Disable file-based analysis
- `-C, --rcf, --rough-control-flow`: Enable rough control flow analysis
- `-D, --rcd, --rough-call-distance`: Enable rough call distance
- `-X, --solver, --path-feasibility`: Enable heuristic Z3 path feasibility check (experimental; does not generate runnable exploits)
- `--json`: Write a structured JSON report to the run log directory
- `--report-dir`: Override the output directory for structured reports
- `--typescript`: Parse standard input as TypeScript (file extensions are detected automatically)
- `-1, --coarse-only`: Coarse analysis only

## Programmatic Usage

```python
from probejs.launcher import unittest_main
from probejs.graph import Graph

# Analyze a file
result, graph = unittest_main(
    file_path='input.js',
    vul_type='os_command'
)

# Access the graph
print(f"Total statements: {graph.get_total_num_statements()}")
print(f"Covered statements: {len(graph.covered_stat)}")
```

### Advanced Programmatic Usage

```python
from probejs.launcher import unittest_main
from probejs.graph import Graph

# Analyze with custom settings
result, graph = unittest_main(
    file_path='app.js',
    vul_type='xss',
    check_signatures=['app.get', 'app.post']
)

# Inspect results
if result:
    print(f"Found {len(result)} vulnerable paths")
    for path in result:
        print(f"  - {path}")

# Access graph statistics
print(f"Total statements: {graph.get_total_num_statements()}")
print(f"Covered statements: {len(graph.covered_stat)}")
print(f"Coverage: {len(graph.covered_stat) / graph.get_total_num_statements() * 100:.2f}%")
```

## Examples

### Example 1: Basic Analysis

```bash
# Analyze a single file for OS command injection
python -m probejs -t os_command examples/vulnerable.js

# Check output in logs directory
cat logs/*/run_log.log
```

### Example 2: Module Analysis

```bash
# Analyze an npm package
python -m probejs -m -t xss package/index.js

# Run all exported functions
python -m probejs -m -a package/index.js
```

### Example 3: Path Feasibility Check (Experimental)

When using the `-X` flag, probejs runs a heuristic Z3-based check on vulnerable paths. This determines whether the path constraints are satisfiable, but **does not generate runnable exploits**:

```bash
python -m probejs -X -t os_command vulnerable.js
```

### Example 4: Structured Reports

Use structured reporting when you want downstream tools or LLM workflows to consume findings directly:

```bash
python -m probejs --json -t os_command vulnerable.js
```

This writes:

- `report.json` - canonical probejs finding data with code snippets, trace rule diagnostics, and path evidence
- `report.schema.json` - the schema for `report.json`

> **Note**: The `pocgen/` directory and `skills/probejs-poc-generation/` contain **experimental** utilities that consume `report.json` to assist with manual PoC generation. These are separate from the core static analysis pipeline and are not part of probejs's automated analysis. See [PoC Generation Workflows](POC_GENERATION.md) for details.

## Advanced Configuration

### Analysis Modes

- **Single Branch Mode** (`-s`): Prevents path explosion by following only one branch at conditional statements. Useful for faster analysis but may miss vulnerabilities.

- **Coarse Analysis** (`-1`): Performs only coarse-grained analysis without detailed path tracking. Faster but less precise.

- **Rough Control Flow** (`-C`): Uses simplified control flow analysis for better performance on large codebases.

### Time Limits

- **Function Timeout** (`-f`): Set maximum execution time per function in seconds. Prevents infinite loops from blocking analysis.

- **Call Limit** (`-c`): Limit the depth of function call chains to analyze. Default is 3.

### Module Analysis

- **Module Mode** (`-m`): Treats input as an npm module, analyzing exported functions and handling `require()` statements.

- **Entry Function** (`-e`): Specifies which function to use as the entry point for analysis.
