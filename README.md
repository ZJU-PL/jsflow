# probejs

**probejs** is a static analysis tool for JavaScript and TypeScript that detects taint-style vulnerabilities via Object Property Graph (OPG) construction and flow-based trace rules. Its canonical machine-readable output is `report.json`.

## Overview

probejs is a JavaScript static analysis framework that:

- **Generates Object Property Graphs (OPG)** from JavaScript source code
- **Statically tracks object property flows** by simulating assignments, property accesses, and function calls
- **Detects taint-style vulnerabilities** including:
  - OS command injection
  - Cross-site scripting (XSS)
  - Code execution vulnerabilities
  - Prototype pollution
  - Internal property tampering
  - Path traversal
  - NoSQL injection
- **Emits structured JSON bug reports** with source snippets, path diagnostics, and trace rule evaluations
- **Exports analysis results** to CSV/TSV format for further processing
- **Supports npm package analysis**

## Architecture

See [docs/source/architecture.rst](docs/source/architecture.rst) for detailed architecture information.

## Installation

### System Requirements

- **Node.js 18.18+ and npm**: Required for JavaScript/TypeScript AST parsing (automated setup)
- **Python 3.8+**: Required for the core analysis engine

### From PyPI (Recommended)

```bash
pip install probejs
```

On first run, the tool will automatically install its JavaScript dependencies
into `~/.cache/probejs/parser/` via `npm install`. You can also trigger this
step manually ahead of time:

```bash
probejs-setup                # or: python -m probejs setup
```

### From Source (Development)

```bash
git clone <repository-url>
cd probejs

# Install Python package in editable mode
pip install -e .

# Install JavaScript parser dependencies
cd probejs/_parser && npm install && cd ../..

# Verify
python -m probejs input.js
```

Or use the provided installation script:
```bash
./install.sh
```

### Python Dependencies

- `networkx` (~=2.4): Graph data structure library
- `z3-solver` (~=4.8.8.0): Heuristic path feasibility check (used only with `-X` flag)
- `sty` (~=1.0.0rc0): Terminal styling and formatting
- `func_timeout` (~=4.3.5): Function timeout handling
- `tqdm` (~=4.48.2): Progress bars for long-running operations

### JavaScript Dependencies

The JavaScript parser scripts are bundled with the Python package and installed
lazily via npm on first use (or via ``probejs-setup``). They include:

- `esprima` (^4.0.1): JavaScript parser for AST generation
- `typescript` (^5.9): Type checking and project/module configuration
- `@typescript-eslint/typescript-estree` (8.42): Original-source TypeScript/TSX parsing
- `source-map` (^0.6.1): Source mapping for generated JavaScript inputs
- `commander` (^3.0.2): Command-line interface utilities
- `ansicolor` (^1.1.84): Terminal color formatting

## Quick Start

```bash
# Analyze a JavaScript or TypeScript file
python -m probejs input.js
python -m probejs input.ts

# Analyze a TypeScript project directory
python -m probejs ./src

# Parse TypeScript supplied on stdin
printf 'const value: string = process.argv[2];' | python -m probejs --typescript -

# Analyze with specific vulnerability type
python -m probejs -t os_command input.js

# Emit a canonical JSON report
python -m probejs --json -t os_command input.js

# Check for prototype pollution
python -m probejs -P input.js

# Disable JS-modeled stubs in builtin_packages/
python -m probejs --no-builtin-packages input.js
```

When `--json` is passed, the JSON report is written to the run log directory as:

- `report.json`: structured bug report with source snippets, path diagnostics, and trace rule evaluations
- `report.schema.json`: schema for the report format

See [docs/source/user_guide/usage.rst](docs/source/user_guide/usage.rst) for detailed usage instructions, examples, and advanced configuration.

### TypeScript support

TypeScript files (`.ts`, `.tsx`, `.mts`, and `.cts`) use a dedicated project frontend that emits probejs's CSV graph directly from an original-source syntax tree. TypeScript is never compiled to JavaScript as part of analysis. The frontend:

- removes type-only syntax while preserving runtime behavior
- converts ES module imports/exports to the existing module-analysis representation
- follows transitive TypeScript imports
- loads the nearest `tsconfig.json` as a type-checking project, including project references
- resolves `baseUrl`/`paths`, package `exports`/`imports`, and workspace packages
- preserves original TypeScript locations and source snippets without source maps
- normalizes TSX and TypeScript-only runtime constructs in memory without compiler helpers
- uses exact ESTree-to-TypeScript node mappings and declaration signatures to identify callback arguments
- records the tested TypeScript compiler and structured diagnostics in `report.json`
- recognizes callback properties in typed options objects and common Fastify, NestJS, EventEmitter, Commander, Yargs, worker, and serverless entrypoints
- consumes existing external or inline JavaScript source maps when analyzing generated CommonJS

Declaration files (`.d.ts`, `.d.mts`, and `.d.cts`) are not runtime files, but their signatures inform callback and promise metadata. Common generated/dependency directories are skipped during directory analysis. Type errors do not prevent conservative runtime analysis. ArkTS `.ets` is intentionally not parsed heuristically; compile it with the matching HarmonyOS toolchain and analyze the resulting JavaScript.

> **Experimental: PoC generation utilities.** The directory `tools/pocgen/` contains experimental utilities that consume `report.json` to assist with proof-of-concept generation. Its `skills/` subdirectory (`tools/pocgen/skills/probejs-poc-generation/`) provides an interactive agent workflow. These are **separate from the core analysis pipeline** and currently rely on LLM-based coding agents (e.g., Codex, Claude) rather than automated symbolic reasoning.

## Documentation

- **[Architecture](docs/source/architecture.rst)**: Detailed architecture, how it works, and output format
- **[Usage Guide](docs/source/user_guide/usage.rst)**: Command-line options, canonical JSON reporting, programmatic usage, and examples
- **[Vulnerability Types](docs/source/user_guide/vulnerability_detection.rst)**: Detailed information about each vulnerability type with examples
- **[Troubleshooting](docs/source/user_guide/troubleshooting.rst)**: Limitations, common issues, debugging tips, and references
- **[Evaluation & Benchmarks](docs/source/user_guide/evaluation.rst)**: Benchmark datasets, regression evaluation, metrics, and current results
- **[PoC Generation Workflows](docs/source/user_guide/poc_generation.rst)**: Difference between the interactive skill and automated runner approaches
- **[PoC Skill](tools/pocgen/skills/probejs-poc-generation/SKILL.md)**: Agent skill for turning `report.json` findings into runnable PoCs
