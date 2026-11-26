#!/usr/bin/env python3
"""Thin entry point so the tool can be called as
``utils/tls_baseline.py <scan|parse|diff|probe> ...``.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tlsbaseline.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
