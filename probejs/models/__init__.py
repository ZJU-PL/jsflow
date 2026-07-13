"""
JavaScript Runtime Models - Built-in JavaScript/Node.js function models.

This package contains Python models that simulate the behavior of JavaScript
built-in objects and Node.js modules during symbolic execution. These models
are essential for accurately tracking data flows through standard library
functions.

Modules:
--------
- modeled_js_builtins: JavaScript built-in objects (Object, Array, String, etc.)
- modeled_builtin_modules: Node.js modules (fs, child_process, http, etc.)

Modeling Approach:
------------------
Each built-in function is modeled to:
1. Track data flow from arguments to return values
2. Mark sources of user input (http requests, process.argv, etc.)
3. Mark sinks where user input would be dangerous
4. Handle common patterns like callback execution

The models create object nodes and edges in the graph to represent the
effects of calling these functions, enabling the analysis to track how
user input propagates through the program.
"""
