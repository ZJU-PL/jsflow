Tutorials
=========

This section provides step-by-step tutorials for using probejs effectively.

Tutorial 1: Basic Vulnerability Detection
-----------------------------------------

In this tutorial, we'll analyze a simple Express.js application for OS command injection vulnerability.

**Step 1: Create a vulnerable application**

Create a file called ``vulnerable_app.js``:

.. code-block:: javascript

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

**Step 2: Run basic analysis**

.. code-block:: bash

   python -m probejs -t os_command vulnerable_app.js

**Step 3: Examine the results**

Check the analysis log:

.. code-block:: bash

   cat logs/*/run_log.log

You should see output indicating that an OS command injection vulnerability was detected.

**Step 4: Path feasibility check (experimental)**

.. code-block:: bash

   python -m probejs -X -t os_command vulnerable_app.js

The solver will attempt to determine whether the path constraints are satisfiable. This does **not** generate runnable exploits — it is a heuristic feasibility check.

Tutorial 2: Prototype Pollution Detection
-----------------------------------------

This tutorial demonstrates how to detect prototype pollution vulnerabilities.

**Step 1: Create a vulnerable merge function**

Create a file called ``proto_pollution.js``:

.. code-block:: javascript

   function merge(target, source) {
       for (let key in source) {
           if (typeof source[key] === 'object' && source[key] !== null) {
               if (!target[key]) target[key] = {};
               merge(target[key], source[key]);
           } else {
               target[key] = source[key];
           }
       }
       return target;
   }

   const userInput = JSON.parse('{"__proto__": {"isAdmin": true}}');
   const config = {};
   merge(config, userInput);

   console.log(({}).isAdmin); // true - prototype polluted!

**Step 2: Analyze for prototype pollution**

.. code-block:: bash

   python -m probejs -P proto_pollution.js

**Step 3: Check results**

.. code-block:: bash

   cat logs/*/proto_pollution.log

Tutorial 3: Module Analysis
---------------------------

This tutorial shows how to analyze npm packages.

**Step 1: Create a simple package**

Create the following files:

``package.json``:
.. code-block:: json

   {
     "name": "vulnerable-package",
     "version": "1.0.0",
     "main": "index.js"
   }

``index.js``:
.. code-block:: javascript

   const express = require('express');
   const app = express();

   module.exports = function() {
       app.get('/eval', (req, res) => {
           const code = req.query.code;
           eval(code); // Vulnerable to code injection
       });

       return app;
   };

**Step 2: Analyze as module**

.. code-block:: bash

   python -m probejs -m -t code_exec index.js

**Step 3: Run all exported functions**

.. code-block:: bash

   python -m probejs -m -a -t code_exec index.js

Tutorial 4: Advanced Configuration
----------------------------------

This tutorial covers advanced analysis options.

**Single Branch Mode**

For faster analysis on large codebases:

.. code-block:: bash

   python -m probejs -s -t xss large_app.js

**Coarse Analysis**

For quick vulnerability scanning:

.. code-block:: bash

   python -m probejs -1 -t os_command app.js

**Function Timeout**

Set time limits to prevent infinite loops:

.. code-block:: bash

   python -m probejs -f 30 -t xss app.js

**Call Depth Limit**

Limit function call chain depth:

.. code-block:: bash

   python -m probejs -c 2 -t nosql app.js

Tutorial 5: Programmatic Usage
------------------------------

This tutorial shows how to use probejs programmatically.

**Step 1: Basic programmatic analysis**

.. code-block:: python

   from probejs.launcher import unittest_main
   from probejs.graph import Graph

   # Analyze a file
   result, graph = unittest_main(
       file_path='vulnerable.js',
       vul_type='os_command'
   )

   # Check results
   if result:
       print(f"Found {len(result)} vulnerable paths")
       for path in result:
           print(f"Vulnerable path: {path}")

**Step 2: Access graph information**

.. code-block:: python

   # Get graph statistics
   total_statements = graph.get_total_num_statements()
   covered_statements = len(graph.covered_stat)
   coverage = covered_statements / total_statements * 100

   print(f"Total statements: {total_statements}")
   print(f"Covered statements: {covered_statements}")
   print(f"Coverage: {coverage:.2f}%")

**Step 3: Custom analysis**

.. code-block:: python

   # Analyze with custom settings
   result, graph = unittest_main(
       file_path='app.js',
       vul_type='xss',
       check_signatures=['app.get', 'app.post'],
       single_branch=True,
       function_timeout=60
   )

Tutorial 6: Batch Analysis
--------------------------

This tutorial demonstrates analyzing multiple files.

**Step 1: Create a batch analysis script**

.. code-block:: python

   import os
   from probejs.launcher import unittest_main

   def analyze_directory(directory, vul_type):
       results = []
       
       for root, dirs, files in os.walk(directory):
           for file in files:
               if file.endswith('.js'):
                   file_path = os.path.join(root, file)
                   print(f"Analyzing {file_path}...")
                   
                   try:
                       result, graph = unittest_main(
                           file_path=file_path,
                           vul_type=vul_type
                       )
                       
                       if result:
                           results.append({
                               'file': file_path,
                               'vulnerabilities': len(result),
                               'paths': result
                           })
                   except Exception as e:
                       print(f"Error analyzing {file_path}: {e}")
       
       return results

   # Usage
   results = analyze_directory('./src', 'os_command')
   
   # Print summary
   print(f"\nAnalysis complete!")
   print(f"Files with vulnerabilities: {len(results)}")
   
   for result in results:
       print(f"{result['file']}: {result['vulnerabilities']} vulnerabilities")

**Step 2: Run batch analysis**

.. code-block:: bash

   python batch_analysis.py

This will analyze all JavaScript files in the specified directory and provide a summary of findings.