Constraint Solver
=================

The ``solver`` module provides constraint solving capabilities using Z3 for path analysis and exploit generation in probejs. It builds constraint systems from operations along vulnerable paths and attempts to find concrete input values that trigger vulnerabilities.

Overview
--------

The constraint solver is responsible for:

* Building constraint systems from data flow operations
* Using Z3 to determine path feasibility
* Generating concrete exploit payloads
* Solving arithmetic, string, and boolean constraints

Key Components
--------------

* **ConstraintBuilder**: Builds constraint systems from graph operations
* **Z3Solver**: Interface to Z3 solver for constraint solving
* **ExploitGenerator**: Generates concrete input values from solutions
* **ConstraintTypes**: Different types of constraints supported

Constraint Types
----------------

The solver handles several types of constraints:

**Arithmetic Constraints:**
* Addition: ``x + y = result``
* Subtraction: ``x - y = result``
* Multiplication: ``x * y = result``
* Division: ``x / y = result``

**String Constraints:**
* Concatenation: ``str1 + str2 = result``
* Substring: ``result.contains(substring)``
* Length: ``len(string) = length_value``
* Equality: ``string1 == string2``

**Boolean Constraints:**
* Logical AND: ``cond1 AND cond2 = result``
* Logical OR: ``cond1 OR cond2 = result``
* Negation: ``NOT cond = result``
* Equality: ``bool1 == bool2``

Constraint Building
-------------------

Constraints are built from operations along vulnerable paths:

.. code-block:: python

   from probejs.core.solver import ConstraintBuilder

   # Create constraint builder
   builder = ConstraintBuilder()

   # Add operations from vulnerable path
   builder.add_operation({
       'type': 'VAR_ASSIGN',
       'args': ['userInput', 'source_value']
   })

   builder.add_operation({
       'type': 'CONCAT',
       'args': ['prefix', 'userInput', 'command']
   })

   # Build constraint system
   constraints = builder.build_constraints()

Example Constraint Generation
-----------------------------

**String Concatenation:**
.. code-block:: python

   # Input: var cmd = "ping " + userInput;
   constraint = {
       'type': 'string_concat',
       'variables': ['cmd', 'userInput'],
       'constants': ['ping '],
       'relationship': 'cmd = "ping " + userInput'
   }

**Arithmetic Operation:**
.. code-block:: python

   # Input: var result = base + userInput;
   constraint = {
       'type': 'arithmetic_add',
       'variables': ['result', 'userInput'],
       'constants': ['base'],
       'relationship': 'result = base + userInput'
   }

**Conditional Check:**
.. code-block:: python

   # Input: if (userInput.length > 0) { ... }
   constraint = {
       'type': 'string_length',
       'variables': ['userInput'],
       'relationship': 'len(userInput) > 0'
   }

Z3 Integration
---------------

The solver uses Z3 through a Python interface:

.. code-block:: python

   from probejs.core.solver import Z3Solver
   import z3

   # Create solver
   solver = Z3Solver()

   # Create Z3 variables
   user_input = z3.String('user_input')
   cmd = z3.String('cmd')

   # Add constraints
   solver.add_constraint(cmd == z3.Concat(z3.StringVal("ping "), user_input))

   # Solve
   if solver.check():
       model = solver.get_model()
       exploit = solver.generate_exploit(model)

Solving Process
---------------

The constraint solving process works as follows:

1. **Path Extraction**: Extract operations from vulnerable data flow path
2. **Constraint Building**: Build constraint system from operations
3. **Z3 Solving**: Use Z3 to find satisfying assignments
4. **Solution Validation**: Validate solutions against original constraints
5. **Exploit Generation**: Generate concrete input values

.. code-block:: python

   def solve_vulnerability(graph, path):
       # Extract operations from path
       operations = graph.extract_operations(path)
       
       # Build constraints
       builder = ConstraintBuilder()
       for op in operations:
           builder.add_operation(op)
       
       constraints = builder.build_constraints()
       
       # Solve with Z3
       solver = Z3Solver()
       for constraint in constraints:
           solver.add_constraint(constraint)
       
       if solver.check():
           model = solver.get_model()
           return solver.generate_exploit(model)
       
       return None

Exploit Generation
------------------

Once constraints are solved, concrete exploits are generated:

.. code-block:: python

   from probejs.core.solver import ExploitGenerator

   generator = ExploitGenerator()

   # Generate exploit from model
   exploit = generator.generate_exploit(model, {
       'userInput': 'string',
       'targetFunction': 'child_process.exec'
   })

   # Result: {'userInput': '; rm -rf /', 'payload': 'ping ; rm -rf /'}

Example Exploits
----------------

**OS Command Injection:**
.. code-block:: python

   # Vulnerable code: exec("ping " + userInput);
   # Generated exploit:
   {
       'userInput': '; cat /etc/passwd',
       'full_command': 'ping ; cat /etc/passwd',
       'vulnerability': 'os_command_injection'
   }

**XSS Exploit:**
.. code-block:: python

   # Vulnerable code: res.send("<h1>" + userInput + "</h1>");
   # Generated exploit:
   {
       'userInput': '<script>alert("XSS")</script>',
       'full_response': '<h1><script>alert("XSS")</script></h1>',
       'vulnerability': 'xss'
   }

**Path Traversal:**
.. code-block-block:: python

   # Vulnerable code: fs.readFile(userInput, callback);
   # Generated exploit:
   {
       'userInput': '../../../etc/passwd',
       'full_path': '../../../etc/passwd',
       'vulnerability': 'path_traversal'
   }

Advanced Constraint Solving
----------------------------

**Complex String Operations:**
.. code-block:: python

   # Handle template literals
   def solve_template_literal(template, variables):
       constraints = []
       for i, part in enumerate(template.parts):
           if isinstance(part, str):
               constraints.append(z3.StringVal(part))
           else:
               constraints.append(variables[part.name])
       
       return z3.Concat(*constraints)

**Array Operations:**
.. code-block:: python

   # Handle array indexing
   def solve_array_access(array_var, index_expr):
       index = solve_expression(index_expr)
       return z3.Select(array_var, index)

**Object Property Access:**
.. code-block:: python

   # Handle property access
   def solve_property_access(obj_var, prop_name):
       return z3.Select(obj_var, z3.StringVal(prop_name))

Solver Configuration
--------------------

The solver can be configured for different scenarios:

.. code-block:: python

   solver_config = {
       'timeout': 30000,  # 30 seconds
       'max_memory': '4GB',
       'random_seed': 42,
       'logic': 'QF_S',  # Quantifier-free strings
       'strategy': 'default'
   }

   solver = Z3Solver(config=solver_config)

Performance Optimization
------------------------

The solver is optimized for performance:

* **Incremental Solving**: Add/remove constraints without rebuilding
* **Parallel Solving**: Solve multiple constraint systems in parallel
* **Caching**: Cache solutions for similar constraint patterns
* **Approximation**: Use approximations for complex constraints

.. code-block:: python

   # Incremental solving example
   solver.push()  # Save current state
   solver.add_constraint(new_constraint)
   
   if solver.check():
       result = solver.get_model()
   
   solver.pop()  # Restore previous state

Limitations
-----------

The constraint solver has several limitations:

* **String Theory**: Z3's string theory has limitations for complex operations
* **Regular Expressions**: Limited support for regex constraints
* **Performance**: Complex constraint systems can be slow to solve
* **Memory Usage**: Large constraint systems consume significant memory

* **Undecidable Problems**: Some constraints may be undecidable
* **Approximation**: Some constraints are approximated rather than solved exactly

Troubleshooting
---------------

**Common Issues:**

* **Solver Timeout**: Increase timeout or simplify constraints
* **Memory Issues**: Reduce constraint complexity or use approximation
* **Unsatisfiable**: Check for contradictory constraints
* **Model Extraction**: Ensure all variables are properly constrained

**Debug Mode:**
.. code-block:: python

   # Enable debug mode
   solver = Z3Solver(debug=True)
   solver.set_log_level('verbose')

   # Export constraints for external analysis
   solver.export_constraints('constraints.smt2')

Future Enhancements
-------------------

Planned improvements to the constraint solver:

* **Enhanced String Theory**: Better support for complex string operations
* **Regex Support**: Full regular expression constraint solving
* **Machine Learning**: Use ML to guide constraint solving
* **Distributed Solving**: Distribute solving across multiple machines