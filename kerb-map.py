#!/usr/bin/env python3
"""
kerb-map — Kerberos Attack Surface Mapper

Thin compatibility shim. The real entry point lives in `kerb_map.cli:main`.
Kept so that `python kerb-map.py ...` and the README's symlink install
(`Option C`) continue to work unchanged.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from kerb_map.cli import main

if __name__ == "__main__":
    main()
