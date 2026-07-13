Esprima Interface
=================

The ``esprima`` module provides the interface between probejs and the Esprima JavaScript parser. It handles parsing JavaScript source code into ASTs and managing the communication with the Node.js Esprima process.

Overview
--------

The esprima interface is responsible for:

* Parsing JavaScript source code into ASTs using Esprima
* Managing the Node.js subprocess that runs Esprima
* Converting Esprima AST format to probejs's internal representation
* Handling parsing errors and edge cases

Architecture
------------

The interface consists of several components:

* **EsprimaParser**: Main parser class that manages the Node.js process
* **ASTConverter**: Converts Esprima AST to internal format
* **ProcessManager**: Handles Node.js subprocess lifecycle
* **ErrorHandler**: Manages parsing errors and exceptions

Installation and Setup
----------------------

The esprima interface requires Node.js and npm dependencies:

.. code-block:: bash

   # Install npm dependencies
   cd esprima-csv && npm install

   # Dependencies installed:
   # - esprima@^4.0.1: JavaScript parser
   # - commander@^3.0.2: CLI framework
   # - ansicolor@^1.1.84: Terminal colors

Basic Usage
-----------

Parsing JavaScript code is straightforward:

.. code-block:: python

   from probejs.core.esprima import parse_js, parse_file

   # Parse JavaScript string
   code = "var x = 42; console.log(x);"
   ast = parse_js(code)

   # Parse JavaScript file
   ast = parse_file("input.js")

The AST is returned as a Python dictionary compatible with the Esprima AST format.

AST Format
----------

The parsed AST follows the Esprima format:

.. code-block:: python

   # Example AST for "var x = 42;"
   ast = {
       'type': 'Program',
       'body': [
           {
               'type': 'VariableDeclaration',
               'declarations': [
                   {
                       'type': 'VariableDeclarator',
                       'id': {
                           'type': 'Identifier',
                           'name': 'x'
                       },
                       'init': {
                           'type': 'Literal',
                           'value': 42
                       }
                   }
               ],
               'kind': 'var'
           }
       ],
       'sourceType': 'script'
   }

Node Types
----------

Common AST node types include:

**Statements:**
* ``VariableDeclaration``: Variable declarations (``var``, ``let``, ``const``)
* ``FunctionDeclaration``: Function declarations
* ``ExpressionStatement``: Expression statements
* ``IfStatement``: Conditional statements
* ``WhileStatement``: While loops
* ``ForStatement``: For loops
* ``ReturnStatement``: Return statements

**Expressions:**
* ``Identifier``: Variable names
* ``Literal``: Literal values (strings, numbers, booleans)
* ``BinaryExpression``: Binary operations (``+``, ``-``, ``*``, ``/``)
* ``UnaryExpression``: Unary operations (``!``, ``-``, ``typeof``)
* ``CallExpression``: Function calls
* ``MemberExpression``: Property access (``obj.prop``)
* ``AssignmentExpression``: Assignments (``=``)

**Structural:**
* ``Program``: Root node of AST
* ``BlockStatement``: Code blocks (``{ ... }``)
* ``FunctionBody``: Function body contents

Process Management
------------------

The esprima interface manages a Node.js subprocess:

.. code-block:: python

   from probejs.core.esprima import EsprimaParser

   # Create parser instance
   parser = EsprimaParser()

   # Parse code (automatically manages process)
   ast = parser.parse("var x = 42;")

   # Cleanup when done
   parser.close()

The process is automatically started on first use and reused for subsequent parses.

Error Handling
--------------

Parsing errors are handled gracefully:

.. code-block:: python

   try:
       ast = parse_js("var x = ;")  # Invalid syntax
   except ParseError as e:
       print(f"Parse error: {e}")
       print(f"Line: {e.lineno}, Column: {e.column}")

Common error types:

* **SyntaxError**: Invalid JavaScript syntax
* **ProcessError**: Node.js process issues
* **TimeoutError**: Parsing timeout
* **IOError**: File I/O problems

Configuration
-------------

The parser can be configured with various options:

.. code-block:: python

   config = {
       'ecma_version': 2018,  # ECMAScript version
       'source_type': 'script',  # 'script' or 'module'
       'allow_return_outside_function': False,
       'allow_hash_bang': False,
       'locations': True,  # Include location info
       'ranges': False,  # Include range info
       'timeout': 30000  # Parse timeout (ms)
   }

   parser = EsprimaParser(config=config)

Advanced Features
-----------------

**Source Maps:**
The parser can handle source maps:

.. code-block:: python

   # Parse with source map support
   ast = parser.parse(code, source_map=True)

**Module Parsing:**
Support for ES6 modules:

.. code-block:: python

   # Parse as ES6 module
   ast = parser.parse(code, source_type='module')

**Comments and Whitespace:**
Preserve comments and whitespace:

.. code-block:: python

   # Parse with comments
   ast = parser.parse(code, attach_comments=True)

Performance Optimization
------------------------

The parser is optimized for performance:

* **Process Reuse**: Node.js process is reused across parses
* **Batch Processing**: Multiple files can be parsed in one process
* **Caching**: Parse results are cached when possible
* **Streaming**: Large files can be streamed

.. code-block:: python

   # Batch parse multiple files
   files = ['file1.js', 'file2.js', 'file3.js']
   asts = parser.parse_batch(files)

   # Stream large file
   ast = parser.parse_stream(large_file.js)

Integration with Graph
----------------------

The parsed AST is integrated with the graph construction:

.. code-block:: python

   from probejs.core.esprima import parse_file
   from probejs.core.graph import Graph

   # Parse JavaScript file
   ast = parse_file('input.js')

   # Create graph and traverse AST
   graph = Graph()
   graph.traverse_ast(ast)

Node.js Interface
-----------------

The Node.js side provides a CLI interface:

.. code-block:: javascript

   // esprima-csv/index.js
   const program = require('commander');
   const esprima = require('esprima');

   program
     .version('1.0.0')
     .option('-f, --file <file>', 'Input file')
     .option('-c, --code <code>', 'Input code')
     .option('--ecma-version <version>', 'ECMAScript version')
     .option('--source-type <type>', 'Source type')
     .parse(process.argv);

   if (program.file) {
     const code = require('fs').readFileSync(program.file, 'utf8');
     const ast = esprima.parseScript(code, options);
     console.log(JSON.stringify(ast));
   }

Communication Protocol
----------------------

Communication between Python and Node.js uses JSON:

.. code-block:: python

   # Python sends request
   request = {
       'type': 'parse',
       'code': 'var x = 42;',
       'options': {
           'ecmaVersion': 2018,
           'sourceType': 'script'
       }
   }

   # Node.js responds with AST
   response = {
       'type': 'ast',
       'ast': {...},
       'error': None
   }

Troubleshooting
---------------

**Common Issues:**

* **Node.js not found**: Install Node.js 12.x or later
* **Port conflicts**: Ensure Node.js process can communicate
* **Memory issues**: Increase Node.js memory limit
* **Parse timeouts**: Increase timeout for large files

**Debug Mode:**
.. code-block:: python

   # Enable debug mode
   parser = EsprimaParser(debug=True)

   # Check process status
   status = parser.get_process_status()
   print(f"Process running: {status['alive']}")

Limitations
-----------

The esprima interface has several limitations:

* **JavaScript Features**: Limited to features supported by Esprima version
* **Performance**: Large files may be slow to parse
* **Memory Usage**: ASTs can consume significant memory
* **Process Management**: Subprocess management adds overhead

Future Enhancements
-------------------

Planned improvements:

* **Multiple Parsers**: Support for alternative JavaScript parsers
* **Worker Threads**: Use worker threads for better performance
* **Incremental Parsing**: Parse only changed portions of files
* **Better Error Recovery**: Improved error handling and recovery