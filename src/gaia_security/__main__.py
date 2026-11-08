"""Executable entry point when running `python -m gaia_security`."""

import sys
from gaia_security.cli import main

if __name__ == "__main__":
    sys.exit(main())
