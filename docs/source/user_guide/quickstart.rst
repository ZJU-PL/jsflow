Quick Start Guide
==================

Get up and running with probejs quickly.

Basic Usage
-----------

Analyze a JavaScript file for vulnerabilities:

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

Command Line Options
--------------------

* ``-p, --print``: Print logs to console instead of file
* ``-t, --vul-type``: Set vulnerability type (``os_command``, ``xss``, ``code_exec``, ``proto_pollution``, ``path_traversal``, ``nosql``)
* ``-P, --prototype-pollution``: Check for prototype pollution
* ``-I, --int-prop-tampering``: Check for internal property tampering
* ``-m, --module``: Module mode (treat input as npm module)
* ``-q, --exit``: Exit when vulnerability is found
* ``-s, --single-branch``: Single branch mode (no path explosion)
* ``-a, --run-all``: Run all exported functions
* ``-f, --function-timeout``: Time limit for function execution (seconds)
* ``-c, --call-limit``: Limit on call statement depth (default: 3)
* ``-e, --entry-func``: Specify entry function name
* ``-F, --nfb, --no-file-based``: Disable file-based analysis
* ``-C, --rcf, --rough-control-flow``: Enable rough control flow analysis
* ``-D, --rcd, --rough-call-distance``: Enable rough call distance
* ``-X, --exploit, --auto-exploit``: Enable automatic exploit generation
* ``-1, --coarse-only``: Coarse analysis only

Example Analysis
-----------------

Analyze a vulnerable JavaScript file:

.. code-block:: javascript

   // vulnerable.js
   const express = require('express');
   const {exec} = require('child_process');
   const app = express();

   app.get('/ping', (req, res) => {
       const host = req.query.host;
       exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
           if (error) {
               res.status(500).send('Error executing ping');
               return;
           }
           res.send(stdout);
       });
   });

   app.listen(3000);

Analysis commands:

.. code-block:: bash

   # Detect OS command injection vulnerability
   python -m probejs -t os_command vulnerable.js

   # Generate exploit payload
   python -m probejs -X -t os_command vulnerable.js

   # Check for prototype pollution
   python -m probejs -P vulnerable.js

Output Files
-------------

Analysis results are saved in timestamped directories under ``logs/`` (e.g., ``logs/20240101_120000/``):

* ``run_log.log``: Main execution log with detected vulnerabilities
* ``graph_log.log``: Graph construction details
* ``opg_nodes.tsv``: Object property graph nodes
* ``opg_rels.tsv``: Object property graph relationships
* ``proto_pollution.log``: Prototype pollution findings (if detected)
* ``int_prop_tampering.log``: Internal property tampering findings (if detected)
* ``vul_func_names.csv``: Detected vulnerable functions

Programmatic Usage
-------------------

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

Advanced Usage
--------------

Constraint Solving
~~~~~~~~~~~~~~~~~~

When using the ``-X`` (auto-exploit) flag, probejs will attempt to generate concrete input values that trigger vulnerabilities:

.. code-block:: bash

   python -m probejs -X -t os_command vulnerable.js

The solver builds constraints from operations like:
- String concatenation: ``result = "prefix" + userInput + "suffix"``
- Numeric addition: ``result = baseValue + userInput``
- Conditional constraints: ``if (userInput.contains("danger"))``

Module Analysis
~~~~~~~~~~~~~~~

.. code-block:: bash

   # Analyze an npm package
   python -m probejs -m -t xss package/index.js

   # Run all exported functions
   python -m probejs -m -a package/index.js

Analysis Modes
~~~~~~~~~~~~~~

* **Single Branch Mode** (``-s``): Prevents path explosion by following only one branch at conditional statements
* **Coarse Analysis** (``-1``): Performs only coarse-grained analysis without detailed path tracking
* **Rough Control Flow** (``-C``): Uses simplified control flow analysis for better performance

Time Limits
~~~~~~~~~~~

* **Function Timeout** (``-f``): Set maximum execution time per function in seconds
* **Call Limit** (``-c``): Limit the depth of function call chains to analyze