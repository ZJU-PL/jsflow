# jsflow

**jsflow** is a static analysis tool for JavaScript that performs vulnerability detection and exploit generation through object graph generation. Its canonical machine-readable output is `report.json`, which is designed to feed downstream workflows such as PoC generation.

## Overview

jsflow is a JavaScript static analysis framework that:

- **Generates Object Property Graphs (OPG)** from JavaScript source code
- **Performs symbolic execution** to track data flows and control flows
- **Detects vulnerabilities** including:
  - OS command injection
  - Cross-site scripting (XSS)
  - Code execution vulnerabilities
  - Prototype pollution
  - Internal property tampering
  - Path traversal
  - NoSQL injection
- **Emits canonical JSON bug reports** with source snippets, path diagnostics, exploit candidates, and PoC-oriented guidance
- **Exports analysis results** to CSV/TSV format for further processing
- **Supports module analysis** for npm packages

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
   cd jsflow
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
- `z3-solver` (~=4.8.8.0): Constraint solving for path analysis
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
python -m jsflow input.js

# Analyze with specific vulnerability type
python -m jsflow -t os_command input.js

# Emit a canonical JSON report
python -m jsflow --json -t os_command input.js

# Check for prototype pollution
python -m jsflow -P input.js

# Disable JS-modeled stubs in builtin_packages/
python -m jsflow --no-builtin-packages input.js
```

The JSON report is written to the run log directory as:

- `report.json`: canonical bug report data
- `report.schema.json`: schema for the report format

Each finding in `report.json` includes a normalized PoC-ready payload under `finding.poc`, plus compatibility guidance under `finding.poc_guidance`.

The PoC-facing `finding.poc` object includes:

- a compact `agent_packet` intended as the default input to coding agents
- target package and entry file details
- invocation mode and candidate call shapes
- source and sink records
- hybrid thin-slice evidence
- deduplicated payload candidates
- suggested oracle
- runtime, harness, and validation hints
- validation state placeholders

This is the intended workflow:

```bash
python -m jsflow --json -m -X -t os_command package/index.js
```

PoC generation has two separate solutions:

- **Interactive skill workflow**: use `skills/jsflow-poc-generation/` for one-off, human-assisted PoC work.
- **Automated runner workflow**: use the `pocgen/` Python runner for reproducible batch generation with Codex/OpenCode/Claude-style CLIs, staged evidence loading, validation, and retries.

Both should use `finding.poc.agent_packet` as the default agent input and treat the rest of `report.json` as an evidence store.

See [docs/USAGE.md](docs/USAGE.md) for detailed usage instructions, examples, and advanced configuration.

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)**: Detailed architecture, how it works, and output format
- **[Usage Guide](docs/USAGE.md)**: Command-line options, canonical JSON reporting, programmatic usage, and examples
- **[Vulnerability Types](docs/VULNERABILITIES.md)**: Detailed information about each vulnerability type with examples
- **[Troubleshooting](docs/TROUBLESHOOTING.md)**: Limitations, common issues, debugging tips, and references
- **[PoC Generation Workflows](docs/POC_GENERATION.md)**: Difference between the interactive skill and automated runner approaches
- **[PoC Skill](skills/jsflow-poc-generation/SKILL.md)**: Agent skill for turning `report.json` findings into runnable PoCs
