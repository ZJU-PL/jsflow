# probejs

**probejs** is a static analysis tool for JavaScript that detects taint-style vulnerabilities via Object Property Graph (OPG) construction and flow-based trace rules. Its canonical machine-readable output is `report.json`.

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

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture information.

## Installation

### Via pyproject.toml (Recommended)

```bash
pip install -e .
```

This installs the package in editable mode with all dependencies defined in `pyproject.toml`.

### System Requirements

- **Node.js and npm**: Required for JavaScript AST parsing dependencies
- **Python 3**: Required for the core analysis engine
- **pip**: Python package manager

### Installation Steps

1. **Clone the repository** (if not already done):
   ```bash
   git clone <repository-url>
   cd probejs
   ```

2. **Install npm dependencies** (for Esprima AST parser):
   ```bash
   cd esprima-csv && npm install && cd ..
   ```
   
   This installs:
   - `esprima` (^4.0.1): JavaScript parser
   - `commander` (^3.0.2): Command-line interface utilities
   - `ansicolor` (^1.1.84): Terminal color output

3. **Set up Python virtual environment** (recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install Python dependencies**:
   ```bash
   pip install -e .
   ```

Alternatively, you can use the provided installation script:
```bash
./install.sh
```

This script will automatically:
- Install npm dependencies in `esprima-csv/`
- Create a Python virtual environment if it doesn't exist
- Activate the virtual environment
- Install all Python dependencies

### Python Dependencies

- `networkx` (~=2.4): Graph data structure library
- `z3-solver` (~=4.8.8.0): Heuristic path feasibility check (used only with `-X` flag)
- `sty` (~=1.0.0rc0): Terminal styling and formatting
- `func_timeout` (~=4.3.5): Function timeout handling
- `tqdm` (~=4.48.2): Progress bars for long-running operations
- `setuptools`: Package building utilities

### Node.js Dependencies

- `esprima` (^4.0.1): JavaScript parser for AST generation
- `commander` (^3.0.2): Command-line interface framework
- `ansicolor` (^1.1.84): Terminal color formatting

## Quick Start

```bash
# Analyze a JavaScript file
python -m probejs input.js

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

See [docs/USAGE.md](docs/USAGE.md) for detailed usage instructions, examples, and advanced configuration.

> **Experimental: PoC generation utilities.** The directories `pocgen/` and `skills/probejs-poc-generation/` contain experimental utilities that consume `report.json` to assist with proof-of-concept generation. These are **separate from the core analysis pipeline** and currently rely on LLM-based coding agents (e.g., Codex, Claude) rather than automated symbolic reasoning.

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)**: Detailed architecture, how it works, and output format
- **[Usage Guide](docs/USAGE.md)**: Command-line options, canonical JSON reporting, programmatic usage, and examples
- **[Vulnerability Types](docs/VULNERABILITIES.md)**: Detailed information about each vulnerability type with examples
- **[Troubleshooting](docs/TROUBLESHOOTING.md)**: Limitations, common issues, debugging tips, and references
- **[PoC Generation Workflows](docs/POC_GENERATION.md)**: Difference between the interactive skill and automated runner approaches
- **[PoC Skill](skills/probejs-poc-generation/SKILL.md)**: Agent skill for turning `report.json` findings into runnable PoCs
