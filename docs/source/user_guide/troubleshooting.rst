Troubleshooting
===============

Limitations
-----------

- **Path Explosion**: Complex programs with many branches may generate exponential execution paths. Use ``-s`` (single branch) or ``-1`` (coarse) modes to mitigate.

- **Dynamic Features**: Highly dynamic JavaScript code (heavy use of ``eval``, dynamic property access, complex prototypes) may not be fully analyzed.

- **False Positives**: Some detected paths may not be exploitable in practice due to:

  - Runtime checks not visible in static analysis
  - Sanitization that isn't recognized
  - Context-specific constraints

- **False Negatives**: Some vulnerabilities may be missed due to:

  - Complex control flow
  - Dynamic code generation
  - Unmodeled library functions

- **Performance**: Large codebases may require significant analysis time. Consider:

  - Using ``-s`` for initial scans
  - Setting function timeouts with ``-f``
  - Limiting call depth with ``-c``

- **Constraint Solving**: The Z3 solver has a timeout (default 2000ms). Complex constraint systems may timeout, resulting in "failed" path analysis.

Common Issues
-------------

1. "Module not found" errors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ensure the JavaScript parser dependencies are installed:

.. code-block:: bash

   probejs-setup                # or: python -m probejs setup

2. Z3 solver timeouts
~~~~~~~~~~~~~~~~~~~~~

Increase timeout in ``solver.py`` or use ``-1`` for coarse analysis.

3. Memory issues
~~~~~~~~~~~~~~~~

Use ``-s`` (single branch) mode or reduce ``-c`` (call limit).

4. No vulnerabilities found
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Try:

- Different vulnerability types (``-t``)
- Module mode (``-m``) if analyzing npm packages
- Check that sources and sinks are properly modeled

5. Analysis hangs
~~~~~~~~~~~~~~~~~

Set function timeout with ``-f`` flag.

Debugging
---------

Enable verbose logging by checking ``logs/*/graph_log.log`` for detailed graph construction information.

References
----------

- **Object Property Graph (OPG)**: Based on the Object Property Graph analysis technique for representing JavaScript code structure
- **Esprima**: JavaScript parser used for AST generation (https://esprima.org/)
- **TypeScript Compiler API**: TypeScript/TSX lowering and module resolution (https://www.typescriptlang.org/)

ArkTS support targets the common ``.ets`` component subset and the same CommonJS analysis boundary. If an application uses vendor syntax that the bundled normalizer cannot lower, build it with the matching HarmonyOS SDK and analyze its CommonJS JavaScript output.

- **NetworkX**: Graph data structure library (https://networkx.org/)
- **Z3**: SMT solver for constraint solving (https://github.com/Z3Prover/z3)
