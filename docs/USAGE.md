# Usage Guide

## Command Line Interface

### Basic Usage

```bash
# Analyze a JavaScript file
python -m jsflow input.js

# Analyze with specific vulnerability type
python -m jsflow -t os_command input.js

# Check for prototype pollution
python -m jsflow -P input.js

# Module mode (analyze as npm module)
python -m jsflow -m input.js

# Exit when vulnerability is found
python -m jsflow -q -t xss input.js

# Print logs to console
python -m jsflow -p input.js
```

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
- `-X, --exploit, --auto-exploit`: Enable automatic exploit generation
- `--json`: Write a structured JSON report to the run log directory
- `--report-dir`: Override the output directory for structured reports
- `-1, --coarse-only`: Coarse analysis only

## Programmatic Usage

```python
from jsflow.launcher import unittest_main
from jsflow.graph import Graph

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
from jsflow.launcher import unittest_main
from jsflow.graph import Graph

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
python -m jsflow -t os_command examples/vulnerable.js

# Check output in logs directory
cat logs/*/run_log.log
```

### Example 2: Module Analysis

```bash
# Analyze an npm package
python -m jsflow -m -t xss package/index.js

# Run all exported functions
python -m jsflow -m -a package/index.js
```

### Example 3: Constraint Solving

When using the `-X` (auto-exploit) flag, jsflow will attempt to generate concrete input values that trigger vulnerabilities:

```bash
python -m jsflow -X -t os_command vulnerable.js
```

### Example 4: Structured Reports

Use structured reporting when you want downstream tools or LLM workflows to consume findings directly:

```bash
python -m jsflow --json -t os_command vulnerable.js
```

This writes:

- `report.json` - canonical jsflow finding data with code snippets, rule diagnostics, and exploit candidates
- `report.schema.json` - the schema for `report.json`

Each finding in `report.json` also includes a `poc_guidance` block with PoC-oriented guidance such as:

- compact `agent_packet` for coding agents
- recovered public entrypoint
- suggested invocation shape
- application-level sink
- deduplicated payload candidates
- suggested oracle
- hybrid thin-slice evidence and runtime hints

Use `finding.poc.agent_packet` as the default input for Codex/OpenCode/Claude-style coding agents. Treat the rest of `finding.poc` and `report.json` as evidence to read only when the compact packet is insufficient or validation fails.

There are two separate PoC generation solutions:

- **Interactive skill workflow**: `skills/jsflow-poc-generation/` for one-off, human-assisted PoC generation.
- **Automated runner workflow**: `pocgen/` Python runner for reproducible batch generation, staged evidence loading, validation, and retries.

See [PoC Generation Workflows](POC_GENERATION.md) for the detailed distinction.

The solver builds constraints from operations like:
- String concatenation: `result = "prefix" + userInput + "suffix"`
- Numeric addition: `result = baseValue + userInput`
- Conditional constraints: `if (userInput.contains("danger"))`

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
