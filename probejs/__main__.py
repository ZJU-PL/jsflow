"""
Main entry point for probejs package.

This module serves as the command-line entry point when probejs is executed
as a Python module (e.g., `python -m probejs input.js`).

Execution Flow:
---------------
1. This module imports and calls main() from launcher.py
2. launcher.main() parses command-line arguments
3. Analysis is performed on the input JavaScript file(s)
4. Results are written to the logs/ directory

Usage:
------
    python -m probejs input.js                    # Basic analysis
    python -m probejs -t xss input.js             # XSS vulnerability check
    python -m probejs -m -t proto_pollution pkg/  # Module mode for npm package
"""

from .launcher import main

main()
