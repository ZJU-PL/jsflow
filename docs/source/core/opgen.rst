Operation Generator
===================

The ``opgen`` module is responsible for traversing JavaScript ASTs and generating the operations that build the object property graph. It serves as the bridge between parsed JavaScript code and the graph-based analysis performed by probejs.

Overview
--------

The operation generator (``opgen``) takes parsed JavaScript AST from Esprima and converts it into a sequence of operations that construct the Object Property Graph (OPG). These operations represent variable assignments, function calls, object property access, and control flow constructs.

Key Components
--------------

* **OperationVisitor**: Main AST visitor class that traverses JavaScript syntax nodes
* **Operation Types**: Different operation types for various JavaScript constructs
* **Context Management**: Maintains execution context during AST traversal

Operation Types
---------------

The operation generator creates several types of operations:

**Variable Operations:**
* ``VAR_DECL``: Variable declaration
* ``VAR_ASSIGN``: Variable assignment
* ``VAR_READ``: Variable read/access

**Object Operations:**
* ``OBJ_CREATE``: Object creation
* ``PROP_WRITE``: Property write/access
* ``PROP_READ``: Property read/access

**Function Operations:**
* ``FUNC_DECL``: Function declaration
* ``FUNC_CALL``: Function call
* ``FUNC_RETURN``: Function return

**Control Flow Operations:**
* ``COND_JUMP``: Conditional jump
* ``UNCOND_JUMP``: Unconditional jump
* ``LABEL``: Jump target label

AST Traversal
-------------

The operation generator uses the visitor pattern to traverse the AST:

.. code-block:: python

   from probejs.core.opgen import OperationVisitor
   from probejs.core.esprima import parse_js

   # Parse JavaScript code
   ast = parse_js("var x = 42;")

   # Create operation visitor
   visitor = OperationVisitor()
   
   # Generate operations
   operations = visitor.visit(ast)

Node Handlers
--------------

Each AST node type has a corresponding handler method:

**ExpressionStatement Handler:**
.. code-block:: python

   def visit_ExpressionStatement(self, node):
       # Handle expression statements
       return self.visit(node['expression'])

**AssignmentExpression Handler:**
.. code-block:: python

   def visit_AssignmentExpression(self, node):
       # Handle variable assignments
       left = self.visit(node['left'])
       right = self.visit(node['right'])
       return self.create_op('VAR_ASSIGN', left, right)

**FunctionDeclaration Handler:**
.. code-block:: python

   def visit_FunctionDeclaration(self, node):
       # Handle function declarations
       func_name = node['id']['name']
       params = [self.visit(param) for param in node['params']]
       body = self.visit(node['body'])
       return self.create_op('FUNC_DECL', func_name, params, body)

Context Management
------------------

The operation generator maintains context during traversal:

**Variable Scope:**
.. code-block:: python

   class OperationContext:
       def __init__(self):
           self.variables = {}
           self.functions = {}
           self.current_scope = 'global'

       def add_variable(self, name, var_info):
           self.variables[self.current_scope][name] = var_info

       def get_variable(self, name):
           return self.variables[self.current_scope].get(name)

**Call Stack:**
.. code-block:: python

   def enter_function(self, func_name, params):
       self.call_stack.append({
           'function': func_name,
           'params': params,
           'return_address': self.current_address
       })

   def exit_function(self):
       return self.call_stack.pop()

Operation Creation
------------------

Operations are created with specific metadata:

.. code-block:: python

   def create_operation(self, op_type, *args, **kwargs):
       return {
           'type': op_type,
           'args': args,
           'lineno': kwargs.get('lineno'),
           'source': kwargs.get('source'),
           'metadata': kwargs.get('metadata', {})
       }

Example Operations
------------------

**Variable Assignment:**
.. code-block:: python

   # Input: var x = 42;
   operation = {
       'type': 'VAR_ASSIGN',
       'args': ['x', 42],
       'lineno': 1,
       'source': 'var x = 42;'
   }

**Function Call:**
.. code-block:: python

   # Input: console.log("Hello");
   operation = {
       'type': 'FUNC_CALL',
       'args': ['console', 'log', ["Hello"]],
       'lineno': 1,
       'source': 'console.log("Hello");'
   }

**Property Access:**
.. code-block:: python

   # Input: obj.prop
   operation = {
       'type': 'PROP_READ',
       'args': ['obj', 'prop'],
       'lineno': 1,
       'source': 'obj.prop'
   }

Integration with Graph
-----------------------

The generated operations are consumed by the Graph class to build the OPG:

.. code-block:: python

   from probejs.core.opgen import OperationVisitor
   from probejs.core.graph import Graph

   # Create graph and operation visitor
   graph = Graph()
   visitor = OperationVisitor()

   # Generate operations from AST
   operations = visitor.visit(ast)

   # Execute operations to build graph
   for op in operations:
       graph.execute_operation(op)

Advanced Features
-----------------

**Control Flow Handling:**
The operation generator handles complex control flow:

.. code-block:: python

   def visit_IfStatement(self, node):
       test = self.visit(node['test'])
       consequent = self.visit(node['consequent'])
       
       # Create conditional jump
       jump_op = self.create_op('COND_JUMP', test, consequent.address)
       
       if node['alternate']:
           alternate = self.visit(node['alternate'])
           jump_op['false_target'] = alternate.address

**Loop Handling:**
.. code-block:: python

   def visit_WhileStatement(self, node):
       test = self.visit(node['test'])
       body = self.visit(node['body'])
       
       # Create loop operations
       loop_start = self.create_label('loop_start')
       loop_test = self.create_op('COND_JUMP', test, body.address)
       loop_jump = self.create_op('UNCOND_JUMP', loop_start.address)

**Exception Handling:**
.. code-block:: python

   def visit_TryStatement(self, node):
       try_block = self.visit(node['block'])
       
       if node['handler']:
           catch_block = self.visit(node['handler'])
           # Create exception handling operations

Performance Considerations
--------------------------

The operation generator is optimized for performance:

* **Lazy Evaluation**: Operations are generated on-demand during traversal
* **Memory Efficiency**: Minimal metadata is stored for each operation
* **Caching**: Frequently accessed patterns are cached
* **Parallel Processing**: Large ASTs can be processed in parallel chunks

Limitations
-----------

* **Dynamic Features**: Limited support for ``eval()`` and ``new Function()``
* **Complex Expressions**: Very complex expressions may not be fully analyzed
* **External Dependencies**: Relies on accurate AST from Esprima
* **Memory Usage**: Large JavaScript files can consume significant memory

For best results with large codebases, consider using:
* Single branch mode (``-s`` flag)
* Function timeout limits (``-f`` flag)
* Coarse analysis mode (``-1`` flag)