Core Components
===============

This section covers the core analysis components and frameworks in probejs.

probejs provides several core modules that work together to perform static analysis of JavaScript code. These components handle parsing, graph construction, symbolic execution, and vulnerability detection.

Overview
--------

At a glance:

* **Graph** (``probejs.core.graph``): Core graph data structure for representing JavaScript code analysis
* **Operation Generator** (``probejs.core.opgen``): AST traversal and static analysis engine
* **Solver** (``probejs.core.solver``): Constraint solving using Z3 for path feasibility checking
* **Trace Rules** (``probejs.core.trace_rule``): Pattern matching rules for vulnerability detection
* **Esprima Interface** (``probejs.core.esprima``): JavaScript parser interface

.. toctree::
   :maxdepth: 2

   graph
   opgen
   solver
   trace_rule
   esprima

API Reference
-------------

For detailed API documentation, please refer to the source code and docstrings within each module. The main classes and functions include:

* **Graph**: Core graph data structure (probejs.core.graph)
* **OperationVisitor**: AST traversal and operation generation (probejs.core.opgen)
* **TraceRule**: Vulnerability detection patterns (probejs.core.trace_rule)
* **Solver**: Constraint solving interface (probejs.core.solver)
* **Esprima Interface**: JavaScript parsing interface (probejs.core.esprima)