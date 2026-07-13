Graph Data Structure
=====================

The ``Graph`` class is the core data structure used by probejs to represent JavaScript code analysis. It wraps a NetworkX MultiDiGraph with extensive helper methods for building and analyzing object property graphs.

Overview
--------

The ``Graph`` class maintains a NetworkX MultiDiGraph that represents:

* **Abstract Syntax Tree (AST) nodes** from parsed JavaScript
* **Object property relationships** between JavaScript objects
* **Data flow edges** (REACHES, POINTS_TO, etc.)
* **Control flow edges** (FLOWS_TO, ENTRY, EXIT)
* **Call relationships** (CALLS)

The graph is built incrementally during symbolic analysis and used for vulnerability detection through path analysis.

Key Attributes
--------------

* ``graph`` (nx.MultiDiGraph): The underlying NetworkX graph
* ``cur_objs`` (list): Current objects being tracked during execution
* ``cur_scope``: Current scope context
* ``covered_stat`` (set): Set of covered statement nodes
* ``all_stat`` (set): Set of all statement nodes
* ``proto_pollution`` (set): Detected prototype pollution nodes
* ``ipt_write`` (set): Internal property tampering write locations
* ``ipt_use`` (set): Internal property tampering use locations
* ``vul_type`` (str): Type of vulnerability being checked
* ``log_dir`` (str): Directory for log files

Graph Edge Types
----------------

The graph uses several edge types to represent different relationships:

**Data Flow Edges:**
* ``REACHES``: Data flow relationships between variables
* ``POINTS_TO``: Object reference relationships
* ``CONTRIBUTES_TO``: How values contribute to expressions (with operation tags)

**Control Flow Edges:**
* ``FLOWS_TO``: Control flow between statements
* ``ENTRY``: Function entry points
* ``EXIT``: Function exit points

**Call Edges:**
* ``CALLS``: Function call relationships

**Property Edges:**
* ``PROPERTY``: Object property access relationships

**Structural Edges:**
* ``PARENT_OF``: Parent-child relationships in AST
* ``CHILD_OF``: Child-parent relationships in AST

Node Types
----------

The graph contains several types of nodes:

* **AST Nodes**: Represent JavaScript syntax elements (statements, expressions, functions)
* **Object Nodes**: Represent JavaScript objects and their properties
* **Scope Nodes**: Represent lexical scopes and variable bindings
* **Artificial Nodes**: Helper nodes for analysis (e.g., DUMMY_STMT)

Usage Examples
---------------

**Basic Graph Creation:**

.. code-block:: python

   from probejs.core.graph import Graph

   # Create a new graph
   G = Graph()
   G.vul_type = 'os_command'

**Adding Nodes:**

.. code-block:: python

   # Add an AST node
   node_id = G.add_ast_node(
       node_type='AST_FUNCTION_DECL',
       code='function test() {}',
       lineno=1,
       endlineno=3
   )

   # Add an object node
   obj_id = G.add_obj_node(
       js_type='object',
       value={'key': 'value'}
   )

**Adding Edges:**

.. code-block:: python

   # Add a data flow edge
   G.add_edge(source_id, target_id, edge_type='REACHES')

   # Add a control flow edge
   G.add_edge(source_id, target_id, edge_type='FLOWS_TO')

**Querying the Graph:**

.. code-block:: python

   # Get successors of a node
   successors = G.get_successors(node_id)

   # Get edges by type
   reaches_edges = G.get_edges_by_type('REACHES')

   # Get nodes by attribute
   func_nodes = G.get_node_by_attr('type', 'AST_FUNCTION_DECL')

**Graph Statistics:**

.. code-block:: python

   # Get total number of statements
   total_statements = G.get_total_num_statements()

   # Get coverage information
   coverage = len(G.covered_stat) / total_statements

   # Export graph data
   G.export_graph_data(output_dir)

Advanced Features
-----------------

**Scope Management:**
The graph tracks lexical scopes and variable bindings:

.. code-block:: python

   # Enter a new scope
   G.enter_scope(scope_name)

   # Add variable to current scope
   G.add_variable_to_scope(var_name, var_node_id)

   # Exit current scope
   G.exit_scope()

**Object Property Tracking:**
The graph maintains detailed information about object properties:

.. code-block:: python

   # Add property to object
   G.add_property_to_object(obj_id, prop_name, prop_value_id)

   # Get object properties
   properties = G.get_object_properties(obj_id)

**Path Analysis:**
The graph supports path-based queries for vulnerability detection:

.. code-block:: python

   # Find paths from source to sink
   paths = G.find_dataflow_paths(source_id, sink_id)

   # Check if path contains vulnerable operation
   is_vulnerable = G.check_path_vulnerability(path)

Export and Visualization
------------------------

The graph can be exported in various formats for analysis and visualization:

**TSV Export:**
.. code-block:: python

   # Export nodes and relationships
   G.export_graph_data('output_directory')

   # This creates:
   # - opg_nodes.tsv: Graph nodes
   # - opg_rels.tsv: Graph relationships

**NetworkX Formats:**
.. code-block:: python

   # Export as NetworkX pickle
   import networkx as nx
   nx.write_gpickle(G.graph, 'graph.pkl')

   # Export as GraphML
   nx.write_graphml(G.graph, 'graph.graphml')

Performance Considerations
--------------------------

The graph data structure is designed for performance with large codebases:

* **Incremental Construction**: Nodes and edges are added incrementally during analysis
* **Efficient Queries**: NetworkX provides optimized graph algorithms
* **Memory Management**: Unused nodes can be garbage collected
* **Indexing**: Frequently accessed nodes are cached for faster lookup

Limitations
-----------

* **Memory Usage**: Large graphs can consume significant memory
* **NetworkX Dependencies**: Relies on NetworkX implementation details
* **Complexity**: The graph structure can be complex for debugging
* **Scalability**: Very large codebases may hit performance limits

For best performance with large codebases, consider using:
* Single branch mode (``-s`` flag)
* Coarse analysis (``-1`` flag)
* Function timeout limits (``-f`` flag)