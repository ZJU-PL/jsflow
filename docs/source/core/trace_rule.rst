Trace Rules
===========

Trace rules define patterns for detecting vulnerabilities in probejs. They specify how data should flow from sources to sinks to constitute a vulnerability, and what operations along the path are considered malicious.

Overview
--------

Trace rules are the core vulnerability detection mechanism in probejs. Each rule defines:

* **Sources**: Where untrusted data originates (e.g., HTTP request parameters)
* **Sinks**: Where vulnerabilities can be exploited (e.g., ``eval()`` function)
* **Operations**: What operations along the data flow path are relevant
* **Sanitizers**: Which functions break the vulnerability chain

Rule Structure
---------------

A trace rule consists of several components:

.. code-block:: python

   class TraceRule:
       def __init__(self):
           self.name = "rule_name"
           self.sources = ["source_function1", "source_function2"]
           self.sinks = ["sink_function1", "sink_function2"]
           self.operations = ["concat", "property_access"]
           self.sanitizers = ["sanitize_function"]
           self.vulnerability_type = "vuln_type"

Built-in Trace Rules
--------------------

probejs includes trace rules for several vulnerability types:

OS Command Injection Rule
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   OS_COMMAND_RULE = TraceRule(
       name="os_command_injection",
       sources=["req.query", "req.body", "req.params"],
       sinks=["child_process.exec", "child_process.execSync", "os.exec"],
       operations=["string_concat", "template_literal"],
       sanitizers=["escapeShellArg"],
       vulnerability_type="os_command"
   )

**Detection Pattern:**
1. Source: HTTP request parameter (``req.query.cmd``)
2. Operations: String concatenation, template literals
3. Sink: ``child_process.exec()`` or similar
4. Vulnerability: Command execution with user input

XSS Rule
~~~~~~~~

.. code-block:: python

   XSS_RULE = TraceRule(
       name="cross_site_scripting",
       sources=["req.query", "req.body", "req.params"],
       sinks=["res.send", "res.write", "res.end", "document.write"],
       operations=["string_concat", "template_literal", "innerHTML"],
       sanitizers=["escapeHtml", "sanitize"],
       vulnerability_type="xss"
   )

**Detection Pattern:**
1. Source: HTTP request parameter (``req.query.name``)
2. Operations: String concatenation, DOM manipulation
3. Sink: ``res.send()`` or ``document.write()``
4. Vulnerability: Script execution in browser context

Code Execution Rule
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   CODE_EXEC_RULE = TraceRule(
       name="code_execution",
       sources=["req.query", "req.body", "req.params"],
       sinks=["eval", "Function", "setTimeout", "setInterval"],
       operations=["string_concat", "template_literal"],
       sanitizers=["jsonParse", "validateCode"],
       vulnerability_type="code_exec"
   )

**Detection Pattern:**
1. Source: HTTP request parameter (``req.body.code``)
2. Operations: String operations
3. Sink: ``eval()`` or ``Function()`` constructor
4. Vulnerability: Arbitrary code execution

Prototype Pollution Rule
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   PROTO_POLLUTION_RULE = TraceRule(
       name="prototype_pollution",
       sources=["req.query", "req.body", "req.params"],
       sinks=["Object.assign", "merge", "extend", "clone"],
       operations=["property_assign", "recursive_merge"],
       sanitizers=["validateKeys", "sanitizeObject"],
       vulnerability_type="proto_pollution"
   )

**Detection Pattern:**
1. Source: User-controlled object
2. Operations: Property assignment, recursive merging
3. Sink: ``__proto__`` or ``constructor.prototype`` modification
4. Vulnerability: Prototype chain modification

Path Traversal Rule
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   PATH_TRAVERSAL_RULE = TraceRule(
       name="path_traversal",
       sources=["req.query", "req.body", "req.params"],
       sinks=["fs.readFile", "fs.writeFile", "fs.unlink", "path.join"],
       operations=["string_concat", "path_operations"],
       sanitizers=["path.normalize", "validatePath"],
       vulnerability_type="path_traversal"
   )

**Detection Pattern:**
1. Source: HTTP request parameter (``req.query.file``)
2. Operations: String concatenation, path operations
3. Sink: File system operations
4. Vulnerability: Access to arbitrary files

NoSQL Injection Rule
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   NOSQL_INJECTION_RULE = TraceRule(
       name="nosql_injection",
       sources=["req.query", "req.body", "req.params"],
       sinks=["db.collection.find", "db.collection.insert", "db.collection.update"],
       operations=["object_construction", "property_assign"],
       sanitizers=["sanitizeQuery", "validateObject"],
       vulnerability_type="nosql_injection"
   )

**Detection Pattern:**
1. Source: HTTP request parameter (``req.body.query``)
2. Operations: Object construction, property assignment
3. Sink: Database query operations
4. Vulnerability: NoSQL query manipulation

Rule Application
----------------

Trace rules are applied during graph analysis:

.. code-block:: python

   from probejs.core.trace_rule import apply_trace_rules

   # Apply all trace rules to graph
   vulnerabilities = apply_trace_rules(graph, trace_rules)

   # Apply specific rule
   os_command_vulns = apply_trace_rules(
       graph, [OS_COMMAND_RULE]
   )

Path Analysis
-------------

The trace rule engine performs path analysis:

1. **Source Identification**: Find nodes matching source patterns
2. **Path Traversal**: Follow data flow edges from sources
3. **Operation Matching**: Check if operations match rule requirements
4. **Sink Identification**: Check if path ends at vulnerable sink
5. **Sanitizer Checking**: Verify no sanitizers break the chain

.. code-block:: python

   def analyze_path(graph, source_node, sink_node, rule):
       path = graph.find_dataflow_path(source_node, sink_node)
       
       if not path:
           return None
       
       # Check operations along path
       operations = graph.extract_operations(path)
       
       for op in operations:
           if op['type'] not in rule.operations:
               return None
           
           # Check for sanitizers
           if is_sanitizer(op, rule.sanitizers):
               return None
       
       return path

Custom Trace Rules
------------------

Users can define custom trace rules:

.. code-block:: python

   from probejs.core.trace_rule import TraceRule

   # Custom SQL injection rule
   SQL_INJECTION_RULE = TraceRule(
       name="sql_injection",
       sources=["req.query", "req.body", "req.params"],
       sinks=["db.query", "connection.query", "sequelize.query"],
       operations=["string_concat", "template_literal"],
       sanitizers=["escapeSql", "parameterize"],
       vulnerability_type="sql_injection"
   )

   # Custom LDAP injection rule
   LDAP_INJECTION_RULE = TraceRule(
       name="ldap_injection",
       sources=["req.query", "req.body", "req.params"],
       sinks=["ldap.search", "ldap.bind"],
       operations=["string_concat", "filter_construction"],
       sanitizers=["escapeLdap", "validateFilter"],
       vulnerability_type="ldap_injection"
   )

Rule Configuration
------------------

Trace rules can be configured for different scenarios:

.. code-block:: python

   rule_config = {
       'strict_mode': True,  # Require exact pattern matches
       'allow_partial': False,  # Don't allow partial path matches
       'max_path_length': 10,  # Maximum path length to consider
       'timeout': 30000,  # Rule application timeout
       'case_sensitive': True  # Case sensitive matching
   }

Sanitizer Detection
-------------------

The engine can detect sanitization functions:

.. code-block:: python

   # Built-in sanitizers
   BUILTIN_SANITIZERS = {
       'html': ['escapeHtml', 'sanitize', 'encodeHtml'],
       'shell': ['escapeShell', 'escapeShellArg', 'shlex.quote'],
       'sql': ['escapeSql', 'mysql.escape', 'pg.escape'],
       'path': ['path.normalize', 'validatePath'],
       'url': ['encodeURI', 'encodeURIComponent']
   }

   # Custom sanitizer detection
   def is_sanitizer(operation, sanitizers):
       if operation['function'] in sanitizers:
           return True
       
       # Check for common sanitizer patterns
       if 'escape' in operation['function'].lower():
           return True
       
       if 'sanitize' in operation['function'].lower():
           return True
       
       return False

Performance Optimization
------------------------

Trace rule application is optimized for performance:

* **Indexing**: Sources and sinks are indexed for fast lookup
* **Caching**: Path analysis results are cached
* **Parallel Processing**: Multiple rules applied in parallel
* **Early Termination**: Rules terminate early when possible

.. code-block:: python

   # Optimized rule application
   def apply_rules_optimized(graph, rules):
       # Pre-compute source and sink nodes
       source_nodes = index_source_nodes(graph, rules)
       sink_nodes = index_sink_nodes(graph, rules)
       
       # Apply rules in parallel
       with ThreadPoolExecutor() as executor:
           futures = []
           for rule in rules:
               future = executor.submit(
                   apply_single_rule, graph, rule, 
                   source_nodes, sink_nodes
               )
               futures.append(future)
           
           results = [future.result() for future in futures]
       
       return flatten(results)

Debugging and Analysis
----------------------

Trace rule execution can be debugged:

.. code-block:: python

   # Enable debug mode
   debug_config = {
       'log_paths': True,
       'log_operations': True,
       'log_sanitizers': True,
       'save_intermediate': True
   }

   # Analyze rule performance
   rule_stats = analyze_rule_performance(graph, rules)
   print(f"Rule application time: {rule_stats['total_time']}ms")
   print(f"Paths analyzed: {rule_stats['paths_analyzed']}")

Limitations
-----------

Trace rules have several limitations:

* **Pattern Matching**: Relies on pattern matching, may miss novel vulnerabilities
* **Context Awareness**: Limited context awareness for complex scenarios
* **Dynamic Features**: Struggles with highly dynamic JavaScript code
* **False Positives**: May report false positives in complex codebases

Future Enhancements
-------------------

Planned improvements to trace rules:

* **Machine Learning**: Use ML to learn vulnerability patterns
* **Context-Aware Rules**: Better context awareness for rule application
* **Dynamic Rule Generation**: Generate rules dynamically from code analysis
* **Community Rules**: Share and import rules from community