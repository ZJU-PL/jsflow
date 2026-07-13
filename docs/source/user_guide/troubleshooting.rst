Troubleshooting
===============

This section covers common issues, limitations, and debugging tips for using probejs.

Common Issues
-------------

Installation Problems
~~~~~~~~~~~~~~~~~~~~~~

**Issue**: "ModuleNotFoundError: No module named 'probejs'"
**Solution**: Ensure you're in the correct directory and the Python virtual environment is activated:

.. code-block:: bash

   cd probejs
   source venv/bin/activate  # On Windows: venv\Scripts\activate

**Issue**: "npm command not found"
**Solution**: Install Node.js and npm from https://nodejs.org/ or use your system package manager.

**Issue**: "Z3 solver not found"
**Solution**: Install Z3 development libraries:

.. code-block:: bash

   # Ubuntu/Debian
   sudo apt-get install libz3-dev

   # macOS
   brew install z3

Parsing Errors
~~~~~~~~~~~~~~

**Issue**: "Failed to parse JavaScript file"
**Solution**: Check that the JavaScript file is syntactically valid. probejs uses Esprima for parsing, so any syntax errors will cause the analysis to fail.

**Issue**: "AST generation failed"
**Solution**: Ensure the esprima-csv dependencies are installed:

.. code-block:: bash

   cd esprima-csv && npm install && cd ..

Analysis Issues
~~~~~~~~~~~~~~~

**Issue**: Analysis takes too long or hangs
**Solution**: Try these options:

.. code-block:: bash

   # Use single branch mode to prevent path explosion
   python -m probejs -s input.js

   # Set function timeout
   python -m probejs -f 30 input.js

   # Use coarse analysis for faster results
   python -m probejs -1 input.js

**Issue**: "Out of memory" error
**Solution**: probejs can use significant memory for large codebases. Try:

.. code-block:: bash

   # Limit call depth
   python -m probejs -c 2 input.js

   # Use coarse analysis
   python -m probejs -1 input.js

**Issue**: No vulnerabilities found but you expect some
**Solution**: Check these possibilities:

* Verify the vulnerability type is correct (``-t`` flag)
* Ensure sources and sinks are properly modeled
* Check if sanitization functions are not recognized
* Try without single branch mode (remove ``-s`` flag)

False Positives
---------------

probejs may report false positives in certain scenarios:

**Unrecognized Sanitization**: If probejs doesn't recognize a sanitization function, it may treat sanitized input as still tainted.

**Solution**: You can extend the built-in function models or use the results as a starting point for manual review.

**Context-Dependent Validation**: Validation that depends on runtime state may not be accurately modeled.

**Solution**: Review the generated paths to determine if they're actually exploitable.

**Dynamic Property Access**: Properties accessed using computed names may not be resolved correctly.

**Solution**: This is a limitation of static analysis. Manual review may be necessary.

Limitations
-----------

JavaScript Features
~~~~~~~~~~~~~~~~~~~

probejs has limited support for certain JavaScript features:

* **Dynamic Code Execution**: ``eval()`` and ``new Function()`` are modeled but complex cases may not be accurate
* **Metaprogramming**: Proxies and Reflect API are not fully supported
* **Async/Await**: Basic support is provided but complex async patterns may not be analyzed correctly
* **ES6 Modules**: CommonJS (``require()``) is better supported than ES6 modules

Third-Party Libraries
~~~~~~~~~~~~~~~~~~~~~

* **Limited Models**: Only commonly used library functions are modeled
* **Version Differences**: Models may not match all library versions
* **Dynamic Loading**: Libraries loaded dynamically may not be analyzed properly

Runtime Dependencies
~~~~~~~~~~~~~~~~~~~~

* **Configuration Files**: Analysis doesn't consider runtime configuration
* **Environment Variables**: Environment-dependent code paths may not be explored
* **Database State**: Database queries are analyzed without considering actual data

Debugging Tips
---------------

Enable Verbose Logging
~~~~~~~~~~~~~~~~~~~~~~

Use the ``-p`` flag to print logs to console:

.. code-block:: bash

   python -m probejs -p input.js

Check Graph Construction
~~~~~~~~~~~~~~~~~~~~~~~~

Examine the graph log to understand how the analysis graph was built:

.. code-block:: bash

   cat logs/*/graph_log.log

Analyze Specific Functions
~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the ``-e`` flag to focus on specific entry functions:

.. code-block:: bash

   python -m probejs -e vulnerableFunction input.js

Export Graph for Visualization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The analysis exports graph data in TSV format that can be loaded into graph analysis tools:

.. code-block:: bash

   # Load nodes and relationships
   head logs/*/opg_nodes.tsv
   head logs/*/opg_rels.tsv

Performance Optimization
------------------------

For large codebases, consider these optimization strategies:

**Incremental Analysis**: Analyze individual modules rather than the entire codebase at once.

**Selective Analysis**: Focus on specific vulnerability types or entry points.

**Memory Management**: Use coarse analysis (``-1`` flag) for large files to reduce memory usage.

**Parallel Processing**: Analyze multiple files in parallel using separate processes.

Getting Help
------------

If you encounter issues not covered here:

1. **Check the logs**: The detailed logs often contain clues about what went wrong
2. **Try simpler examples**: Test with minimal examples to isolate the problem
3. **Review the options**: Ensure you're using the appropriate command-line flags
4. **Check file formats**: Ensure JavaScript files are properly formatted and encoded

Best Practices
--------------

To get the most reliable results from probejs:

* **Start Simple**: Begin with basic analysis and add complexity as needed
* **Review Results**: Always manually review the reported vulnerabilities
* **Combine Tools**: Use probejs alongside other security tools for comprehensive coverage
* **Keep Models Updated**: Extend built-in models for your specific libraries and frameworks
* **Test Regularly**: Incorporate probejs into your CI/CD pipeline for continuous security monitoring

Known Issues
------------

* **Large Files**: Analysis of very large JavaScript files (>10MB) may cause memory issues
* **Complex Regex**: Regular expressions with complex patterns may not be analyzed accurately
* **Type Coercion**: JavaScript's type coercion behavior is not perfectly modeled
* **Browser APIs**: Browser-specific APIs are less well-modeled than Node.js APIs

These issues are actively being worked on in future releases.