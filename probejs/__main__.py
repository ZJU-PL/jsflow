"""
Main entry point for probejs package.

This module serves as the command-line entry point when probejs is executed
as a Python module (e.g., ``python -m probejs input.js``).

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
    python -m probejs setup                       # Install JS parser deps
"""

import sys

from .launcher import main


def _is_setup_command() -> bool:
    """Detect ``probejs setup`` (or ``probejs install``) subcommand."""
    return len(sys.argv) >= 2 and sys.argv[1] in ("setup", "install")


if __name__ == "__main__":
    # The ``probejs setup`` subcommand must be handled before the argument
    # parser in launcher.main() sees it (otherwise it would be interpreted as
    # the positional ``input_file``).
    if _is_setup_command():
        from ._setup import main as setup_main

        # Strip the subcommand so argparse in _setup.py gets clean args.
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        setup_main()
    else:
        main()
