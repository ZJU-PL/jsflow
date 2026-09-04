Usage Guide
===========

Command Line Interface
----------------------

Basic Usage
~~~~~~~~~~~

.. code-block:: bash

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

TypeScript
~~~~~~~~~~

TypeScript files are detected from their extension and use the same commands as JavaScript:

.. code-block:: bash

   python -m probejs src/index.ts
   python -m probejs --json -t os_command src/index.ts
   python -m probejs ./src

Supported source extensions are ``.ts``, ``.tsx``, ``.mts``, and ``.cts``. A dedicated frontend reads the nearest ``tsconfig.json``, parses original source, performs analysis-oriented in-memory normalization, and emits the same CSV contract used by the unchanged graph engine. Project references, ``baseUrl``, ``paths``, package ``exports``/``imports``, and npm/pnpm-style workspaces are resolved without compiling TypeScript to JavaScript.

ArkTS ``.ets`` is not accepted by this frontend. Compile ArkTS with the matching HarmonyOS toolchain and analyze the generated JavaScript instead.

For TypeScript read from standard input, pass ``--typescript`` explicitly because stdin has no filename:

.. code-block:: bash

   printf 'const input: string = process.argv[2];' | python -m probejs --typescript -

Type-only constructs are erased from the analyzed program. Declaration signatures are retained as compact metadata for callback registration and promise-returning APIs, but probejs remains a runtime-oriented flow analysis rather than a TypeScript type checker.

When JSON reporting is enabled, ``frontend.compilers`` records the tested TypeScript compiler and ``frontend.diagnostics`` contains structured syntax, configuration, module-resolution, and semantic diagnostics. Diagnostics do not prevent conservative runtime analysis.

Command Line Options
~~~~~~~~~~~~~~~~~~~~

- ``-p, --print``: Print logs to console instead of file
- ``-t, --vul-type``: Set vulnerability type (``os_command``, ``xss``, ``code_exec``, ``proto_pollution``, ``path_traversal``, ``nosql``)
- ``-P, --prototype-pollution``: Check for prototype pollution
- ``-I, --int-prop-tampering``: Check for internal property tampering
- ``-m, --module``: Module mode (treat input as npm module)
- ``-q, --exit``: Exit when vulnerability is found
- ``-s, --single-branch``: Single branch mode (no path explosion)
- ``-a, --run-all``: Run all exported functions
- ``-f, --function-timeout``: Time limit for function execution (seconds)
- ``-c, --call-limit``: Limit on call statement depth (default: 3)
- ``-e, --entry-func``: Specify entry function name
- ``-F, --nfb, --no-file-based``: Disable file-based analysis
- ``-C, --rcf, --rough-control-flow``: Enable rough control flow analysis
- ``-D, --rcd, --rough-call-distance``: Enable rough call distance
- ``-X, --solver, --path-feasibility``: Enable heuristic Z3 path feasibility check (experimental; does not generate runnable exploits)
- ``--json``: Write a structured JSON report to the run log directory
- ``--report-dir``: Override the output directory for structured reports
- ``--typescript``: Parse standard input as TypeScript (file extensions are detected automatically)
- ``-1, --coarse-only``: Coarse analysis only
- ``--no-builtin-packages``: Disable JS-modeled stubs for built-in Node modules (shipped in ``probejs/builtin_packages/``). Useful when evaluating against plain JavaScript code to avoid the influence of modeled API behaviour.

Programmatic Usage
------------------

.. code-block:: python

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

Advanced Programmatic Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

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

Examples
--------

Example 1: Basic Analysis
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Analyze a single file for OS command injection
   python -m probejs -t os_command examples/vulnerable.js

   # Check output in logs directory
   cat logs/*/run_log.log

Example 2: Module Analysis
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Analyze an npm package
   python -m probejs -m -t xss package/index.js

   # Run all exported functions
   python -m probejs -m -a package/index.js

Example 3: Path Feasibility Check (Experimental)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using the ``-X`` flag, probejs runs a heuristic Z3-based check on vulnerable paths. This determines whether the path constraints are satisfiable, but **does not generate runnable exploits**:

.. code-block:: bash

   python -m probejs -X -t os_command vulnerable.js

Example 4: Structured Reports
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use structured reporting when you want downstream tools or LLM workflows to consume findings directly:

.. code-block:: bash

   python -m probejs --json -t os_command vulnerable.js

This writes:

- ``report.json`` - canonical probejs finding data with code snippets, trace rule diagnostics, and path evidence
- ``report.schema.json`` - the schema for ``report.json``

.. note::

   The ``tools/pocgen/`` directory contains **experimental** utilities that consume ``report.json`` to assist with manual PoC generation. These are separate from the core static analysis pipeline and are not part of probejs's automated analysis. See :doc:`poc_generation` for details.

Advanced Configuration
----------------------

Analysis Modes
~~~~~~~~~~~~~

- **Single Branch Mode** (``-s``): Prevents path explosion by following only one branch at conditional statements. Useful for faster analysis but may miss vulnerabilities.

- **Coarse Analysis** (``-1``): Performs only coarse-grained analysis without detailed path tracking. Faster but less precise.

- **Rough Control Flow** (``-C``): Uses simplified control flow analysis for better performance on large codebases.

Time Limits
~~~~~~~~~~~

- **Function Timeout** (``-f``): Set maximum execution time per function in seconds. Prevents infinite loops from blocking analysis.

- **Call Limit** (``-c``): Limit the depth of function call chains to analyze. Default is 3.

Module Analysis
~~~~~~~~~~~~~~~

- **Module Mode** (``-m``): Treats input as an npm module, analyzing exported functions and handling ``require()`` statements.

- **Entry Function** (``-e``): Specifies which function to use as the entry point for analysis.
