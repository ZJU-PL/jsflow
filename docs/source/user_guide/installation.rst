Installation Guide
==================

Installation guide for probejs and its dependencies.

Prerequisites
-------------

* **Python 3.8+**: Core analysis engine
* **Node.js 18.18+**: JavaScript and TypeScript frontend execution
* **pip**: Python package manager

From PyPI
---------

.. code-block:: bash

   pip install probejs

On first run, the tool automatically installs its JavaScript dependencies into
``~/.cache/probejs/parser/`` via ``npm install``. You can also trigger this step
manually:

.. code-block:: bash

   probejs-setup                # or: python -m probejs setup

From Source (Development)
-------------------------

.. code-block:: bash

   git clone <repository-url>
   cd probejs

   # Install Python package in editable mode
   pip install -e .

   # Install JavaScript parser dependencies
   cd probejs/_parser && npm install && cd ../..

   # Verify
   python -m probejs --help

Alternatively, use the provided installation script:

.. code-block:: bash

   ./install.sh

This will:
- Install npm dependencies in ``probejs/_parser/``
- Create a Python virtual environment if it doesn't exist
- Activate the virtual environment
- Install all Python dependencies

Python Dependencies
-------------------

* ``networkx`` (~=2.4): Graph data structure library
* ``z3-solver`` (~=4.8.8.0): Constraint solving for path analysis
* ``sty`` (~=1.0.0rc0): Terminal styling and formatting
* ``func_timeout`` (~=4.3.5): Function timeout handling
* ``tqdm`` (~=4.48.2): Progress bars for long-running operations
* ``setuptools``: Package building utilities

JavaScript Dependencies
-----------------------

The JavaScript parser scripts are bundled with the Python package and installed
lazily via npm on first use (or via ``probejs-setup``). They include:

* ``esprima`` (^4.0.1): JavaScript parser for AST generation
* ``typescript`` (^5.9): Type checking and project/module configuration
* ``@typescript-eslint/typescript-estree`` (8.42): Original-source TypeScript/TSX parsing
* ``source-map`` (^0.6.1): Source mapping for generated JavaScript inputs
* ``commander`` (^3.0.2): Command-line interface framework
* ``ansicolor`` (^1.1.84): Terminal color formatting

Verification
------------

To verify the installation:

.. code-block:: bash

   # Test basic functionality
   python -m probejs --help

   # Test with a simple JavaScript file
   echo "console.log('Hello, World!');" > test.js
   python -m probejs test.js

If the installation is successful, you should see the help message and analysis
output without errors. The JavaScript parser dependencies will be installed
automatically on first use if they are not already present.

Troubleshooting
---------------

* **Node.js not found**: Install Node.js 18.18 or later via your package manager
  or from https://nodejs.org/
* **npm install fails**: The parser setup runs ``npm install`` automatically.
  If it fails, try running ``probejs-setup --force``.
* **Python import errors**: Ensure you're using the correct Python environment
  and that all dependencies are installed.
* **Permission errors**: Use a virtual environment or install with ``--user`` flag.
