Installation Guide
==================

Installation guide for probejs and its dependencies.

Prerequisites
-------------

* **Python 3.7+**: Core analysis engine
* **Node.js 12+**: JavaScript AST parsing (Esprima)
* **Z3 4.8+**: Constraint solving for exploit generation
* **pip**: Python package manager

Installation Steps
------------------

1. **Clone the repository**:
   .. code-block:: bash

      git clone <repository-url>
      cd probejs

2. **Install npm dependencies** (for Esprima AST parser):
   .. code-block:: bash

      cd esprima-csv && npm install && cd ..

   This installs:
   - ``esprima`` (^4.0.1): JavaScript parser
   - ``commander`` (^3.0.2): Command-line interface utilities
   - ``ansicolor`` (^1.1.84): Terminal color output

3. **Set up Python virtual environment** (recommended):
   .. code-block:: bash

      python3 -m venv venv
      source venv/bin/activate  # On Windows: venv\Scripts\activate

4. **Install Python dependencies**:
   .. code-block:: bash

      pip install -r requirements.txt

Alternatively, you can use the provided installation script:
.. code-block:: bash

   ./install.sh

This script will automatically:
- Install npm dependencies in ``esprima-csv/``
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

Node.js Dependencies
--------------------

* ``esprima`` (^4.0.1): JavaScript parser for AST generation
* ``commander`` (^3.0.2): Command-line interface framework
* ``ansicolor`` (^1.1.84): Terminal color formatting

Z3 Installation
---------------

**Ubuntu/Debian**:
.. code-block:: bash

   sudo apt-get install libz3-dev

**macOS with Homebrew**:
.. code-block:: bash

   brew install z3

**From source**:
.. code-block:: bash

   git clone https://github.com/Z3Prover/z3.git
   cd z3 && python scripts/mk_make.py
   cd build && make && sudo make install

Verification
------------

To verify the installation:

.. code-block:: bash

   # Test basic functionality
   python -m probejs --help

   # Test with a simple JavaScript file
   echo "console.log('Hello, World!');" > test.js
   python -m probejs test.js

If the installation is successful, you should see the help message and analysis output without errors.

Troubleshooting
---------------

* **Node.js not found**: Install Node.js 12.x or later via your package manager or from https://nodejs.org/
* **Z3 not found**: Install Z3 or set ``Z3_DIR`` environment variable
* **npm install fails**: Try clearing npm cache with ``npm cache clean --force``
* **Python import errors**: Ensure you're using the correct Python environment and that all dependencies are installed
* **Permission errors**: Use a virtual environment or install with ``--user`` flag