Esprima Interface
=================

The ``esprima`` module provides the Python bridge to the bundled JavaScript/TypeScript parsing
scripts shipped in ``probejs/_parser/``. It handles parsing JavaScript and TypeScript source code
into the CSV/AST form consumed by the analysis pipeline, and provides module resolution helpers.

Overview
--------

The esprima interface is responsible for:

* Parsing JavaScript and TypeScript files into the shared AST/CSV contract using separate language frontends
* Resolving Node-style and tsconfig-aware module entry points
* Discovering the transitive file set loaded by ``require(...)``
* Managing the lazy installation of JavaScript parser dependencies on first use

Architecture
------------

The interface consists of several components:

* **``esprima_parse()``**: Main parsing function that invokes the Node.js parser via subprocess
* **``esprima_search()``**: Module resolution using the bundled Node-side resolver
* **``get_file_list()``**: Transitive file discovery for a ``require()`` call
* **``_setup`` integration**: The parser's npm dependencies are installed lazily via ``probejs._setup.get_parser_dir()``

Unlike the older documentation described, there is no ``EsprimaParser`` class, no ``parse_js``/
``parse_file`` convenience functions, and no persistent Node.js subprocess. Each call spawns a
fresh ``node`` process for simplicity and reliability.

Parser Lifecycle
----------------

The JavaScript scripts are shipped as package data (``probejs/_parser/``) but their npm
dependencies (``esprima``, ``typescript``, etc.) are **not** bundled in the wheel. On the first
call to any function in this module, ``probejs._setup.get_parser_dir()`` copies the scripts to
``~/.cache/probejs/parser/`` and runs ``npm install``. Subsequent calls reuse the cached copy.

.. code-block:: bash

   # Install JavaScript parser dependencies manually ahead of time
   probejs-setup                # or: python -m probejs setup

   # Dependencies installed:
   # - esprima@^4.0.1: JavaScript parser
   # - commander@^3.0.2: CLI framework
   # - ansicolor@^1.1.84: Terminal colors
   # - typescript@^5.9: Type checking and project configuration
   # - @typescript-eslint/typescript-estree@8.42: TypeScript/TSX parsing
   # - source-map@^0.6.1: Generated JavaScript source-map support

Basic Usage
-----------

Parsing JavaScript code:

.. code-block:: python

   from probejs.core.esprima import esprima_parse

   # Parse a file
   csv_output = esprima_parse("input.js")

   # Parse from stdin
   csv_output = esprima_parse("-", input='var x = 42;')

   # Pass extra CLI flags
   csv_output = esprima_parse("input.ts", args=["--json"])

The returned string is a CSV or JSON payload emitted by the parser script. The caller
(typically ``opgen``) is responsible for decoding it.

Module Resolution
-----------------

Resolve a Node-style module import:

.. code-block:: python

   from probejs.core.esprima import esprima_search

   main_path, module_dir = esprima_search("express", "/path/to/project")
   print(f"Main entry: {main_path}")
   print(f"Module dir: {module_dir}")

This mirrors Node.js resolution closely enough for probejs's module analysis. It returns
both the discovered main file and the resolved module directory.

.. code-block:: python

   # Disable JS-modeled built-in packages
   main_path, module_dir = esprima_search(
       "express",
       "/path/to/project",
       disable_builtin_packages=True
   )

Transitive File Discovery
-------------------------

Discover which files Node touches when evaluating ``require(...)``:

.. code-block:: python

   from probejs.core.esprima import get_file_list

   files = get_file_list("child_process")
   print(files)
   # e.g., ['child_process.js', 'child_process/promise.js', ...]

This is useful for tests and higher-level tooling to reason about the module closure.

Command-line Scripts
--------------------

The Node.js scripts bundled in ``probejs/_parser/`` include:

``main.js`` - JavaScript parsing entry point and internal CSV encoder:
   - Accepts a file path or ``-`` for stdin
   - Parses JavaScript with Esprima
   - Outputs a CSV/AST representation on stdout

``typescript-main.js`` - TypeScript project frontend:
   - Parses ``.ts``, ``.tsx``, ``.mts``, and ``.cts`` from original source
   - Loads the nearest ``tsconfig.json`` and TypeScript checker
   - Normalizes type-only and TypeScript runtime constructs in memory
   - Emits the shared CSV contract without compiling TypeScript to JavaScript

``search.js`` - Module resolution helper:
   - Resolves ``require()`` paths using Node-style walk-up search
   - Respects ``tsconfig.json`` baseUrl/paths and package.json exports/imports
   - Supports the built-in package stubs in ``~/.cache/probejs/builtin_packages/``

Communication Protocol
----------------------

Communication between Python and Node.js uses stdin/stdout:

.. code-block:: python

   # Python sends file path as CLI argument
   proc = subprocess.Popen(
       ["node", "main.js", "input.js"],
       stdout=subprocess.PIPE,
       stderr=subprocess.PIPE
   )

   # Node.js responds with CSV/AST on stdout
   stdout, stderr = proc.communicate()

The parser writes progress and diagnostic information to stderr. The analysis-relevant
payload (CSV or JSON AST) is written to stdout.

Troubleshooting
---------------

**Common Issues:**

* **Node.js not found**: Install Node.js 18.18 or later from https://nodejs.org/
* **npm install fails**: Run ``probejs-setup --force`` to reinstall
* **Parse errors**: The parser reports syntax errors on stderr; check ``run_log.log``
* **Timeout for large files**: Increase timeout via the ``-t`` flag if supported by the parser script

**Debug Mode:**
Check ``logs/*/run_log.log`` for parser stderr output, which includes detailed
information about parsing progress and any errors encountered.

Limitations
-----------

* Each ``esprima_parse()`` call spawns a fresh ``node`` subprocess — no persistent process reuse
* The CSV/AST output format is an internal representation; prefer ``--json`` for structured output
* ArkTS ``.ets`` requires pre-compilation with the matching HarmonyOS toolchain
