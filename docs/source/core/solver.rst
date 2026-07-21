Constraint Solving in probejs
=============================

Overview
--------

probejs uses **Z3** (an SMT solver) to solve constraints and determine if vulnerable paths are feasible, and to generate concrete exploit payloads. The system models string concatenations and numeric operations along data flow paths.

Architecture
------------

Two implementations exist:

1. **Legacy Solver** (``probejs/core/solver.py``): Direct Z3 constraint building from graph edges
2. **New Constraint Engine** (``probejs/constraints/engine.py``): Expression IR-based approach

The legacy solver (``solve2()``) is currently the active implementation.

Path-Sensitive Engine
---------------------

New APIs: ``build_path_constraints``, ``encode_path_constraint``, ``solve_path_sensitive``

- Tracks path conditions alongside value expressions (branch predicates, sanitizers, edge guards)
- Preserves choices per-branch instead of collapsing them
- Use when you have a concrete source→sink path and want full path conditions encoded before Z3 solving

Key Concepts
------------

CONTRIBUTES_TO Edges
~~~~~~~~~~~~~~~~~~~~

Tracks value flow through operations. Each edge has an ``opt`` attribute: ``(operation_type, group_id, operand_index)``.

Example: ``result = "prefix" + userInput + "suffix"`` creates three edges with ``("string_concat", "group1", 0/1/2)``.

Mixed Symbols
~~~~~~~~~~~~~

JavaScript values can be strings or numbers. ``MixedSymbol`` objects hold both:

- String view: ``z3.String(f"s{node_id}")``
- Numeric view: ``z3.Real(f"n{node_id}")``

Constraint Building Process
~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Start from sink objects (vulnerable function parameters)
2. Backward traversal: Follow ``CONTRIBUTES_TO`` edges to find sources
3. Group operations by type and group ID
4. Build Z3 constraints: ``string_concat`` → ``z3.Concat(...)``, ``numeric_add`` → ``z3.Sum(...)``
5. Add literal and security constraints
6. Solve with Z3 (2-second timeout)

Legacy Solver (``solve2``)
--------------------------

.. code-block:: python

   def solve2(G: Graph, final_objs, initial_objs=None, contains=True):
       """
       Solve constraints to determine if vulnerable paths are feasible.

       Args:
           G: Graph containing analysis results
           final_objs: List of sink object node IDs
           initial_objs: Optional list of source object node IDs
           contains: If True, use substring match for sink values; if False, use equality

       Yields:
           (assertions, results) tuples where results is "failed" if unsat,
           or dict of variable→value mappings (exploit)
       """

**Process:**

1. Creates ``MixedSymbol`` objects for each node
2. Traverses backward from sinks using a queue
3. Groups contributors by operation and builds Z3 constraints
4. Applies security constraints from ``G.extra_constraints``
5. Solves and extracts model

New Constraint Engine
---------------------

The new engine (``probejs/constraints/engine.py``) uses an Expression IR:

**Core Expression Types:**

- ``ConstString``, ``ConstNumber``: Constants
- ``Symbol``: Graph node reference
- ``Concat``, ``Add``: Operations
- ``Choice``: Multiple possible expressions
- ``PathConstraint``: Expression + path condition

**Key Functions:**

- ``build_expressions()``: Builds expression DAGs by following ``CONTRIBUTES_TO`` edges backward
- ``encode_to_z3()``: Converts Expression DAG to Z3 terms

**Path-Sensitive Solving:**

.. code-block:: python

   from probejs.constraints import solve_path_sensitive

   G.solve_from = "; rm -rf /"
   for assertions, results in solve_path_sensitive(
       G, final_objs=[sink_obj], path_nodes=path_nodes
   ):
       if results != "failed":
           print("Exploit found", results)

Usage Example
-------------

.. code-block:: python

   from probejs.core.solver import solve2

   G.solve_from = "; rm -rf /"  # OS command injection payload
   for assertions, results in solve2(G, final_objs=[sink_obj_id], initial_objs=[source_obj_id]):
       if results != "failed":
           print("Exploit found!")
           for var_name, (human_name, value) in results.items():
               print(f"{human_name} = {value}")

Supported Operations
--------------------

- **String**: ``string_concat``, ``array_join`` → ``z3.Concat(...)``
- **Numeric**: ``numeric_add`` → ``z3.Sum(...)``, ``sub`` → subtraction
- **Unknown**: ``unknown_add`` (tries string first, falls back to numeric)
- **Other**: ``UnknownOp`` creates fresh symbol

Constraints
-----------

- **Literals**: Constants from graph nodes (``symbol.string() == z3.StringVal("literal")``)
- **Sinks**: ``contains=True`` → ``z3.Contains()``, ``contains=False`` → equality
- **Security**: From ``G.extra_constraints`` (``not-contains``, ``contains``)
- **Default**: Prevents command chaining (``;``) and HTML entity encoding (``&``)

Limitations
-----------

1. Only models basic string/numeric operations
2. Limited JavaScript type coercion handling
3. 2-second solver timeout
4. Z3 string theory limitations
5. Legacy solver models all paths together (not path-sensitive)

Future Improvements
-------------------

The new constraint engine provides a foundation for better operation modeling, type handling, path-sensitive solving, and support for more JavaScript operations.
