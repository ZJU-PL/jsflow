probejs: JavaScript Static Analysis Framework
============================================

probejs is a comprehensive static analysis framework for JavaScript that performs vulnerability detection and exploit generation through object property graph generation and symbolic execution.

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   user_guide/installation
   user_guide/quickstart
   user_guide/tutorials
   user_guide/vulnerability_detection
   user_guide/troubleshooting

.. toctree::
   :maxdepth: 2
   :caption: Core Components

   core/index

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   core/index
   analysis/index
   constraints/index
   models/index
   utils/index
   tools/index


Features
--------

* **Object Property Graph Generation**: Creates detailed graphs representing JavaScript object relationships and data flows
* **Symbolic Execution**: Performs path-sensitive analysis with constraint solving using Z3
* **Vulnerability Detection**: Identifies multiple vulnerability types including OS command injection, XSS, prototype pollution, and more
* **Exploit Generation**: Automatically generates concrete input values to trigger detected vulnerabilities
* **Module Analysis**: Supports npm package analysis with proper handling of require() statements
* **Export Capabilities**: Results can be exported to CSV/TSV format for further analysis

Supported Vulnerability Types
------------------------------

* **OS Command Injection**: Unsafe execution of user-controlled input
* **Cross-Site Scripting (XSS)**: User input reaching HTTP responses without sanitization
* **Code Execution**: Dynamic code execution with user input (eval, Function constructor)
* **Prototype Pollution**: Modifications to JavaScript object prototypes
* **Internal Property Tampering**: Changes to internal object properties
* **Path Traversal**: File operations with unsanitized user-provided paths
* **NoSQL Injection**: Unsafe NoSQL query construction

Architecture Overview
---------------------

probejs consists of several key components:

* **Core Analysis Engine**: Graph construction, symbolic execution, and constraint solving
* **Vulnerability Detection**: Pattern matching and trace rule application
* **JavaScript Models**: Built-in function and module modeling
* **Command-Line Interface**: User-friendly tools for analysis

The analysis pipeline works as follows:

1. **Parsing**: JavaScript source is parsed into AST using Esprima
2. **Graph Construction**: AST is converted into NetworkX MultiDiGraph with object relationships
3. **Symbolic Execution**: Path-sensitive analysis tracks data flows and control flows
4. **Vulnerability Detection**: Trace rules identify paths from sources to vulnerable sinks
5. **Constraint Solving**: Z3 solver determines path feasibility and generates exploits

Requirements
------------

* **Python 3.7+**: Core analysis engine
* **Node.js 12+**: JavaScript AST parsing (Esprima)
* **Z3 4.8+**: Constraint solving for exploit generation
* **NetworkX 2.4+**: Graph data structures

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`