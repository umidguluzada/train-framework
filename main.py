#!/usr/bin/env python3
"""
TRAIN Framework - Threat Response & Automated Intelligence Network
Entry point.
"""

import sys

from core.tui_engine import run
from core import bridge              # noqa: F401
from modules import web_auditor      # noqa: F401
from modules import crypto_utils     # noqa: F401
from modules import pass_auditor     # noqa: F401
from modules import script_engine    # noqa: F401
from modules import cve_lookup       # noqa: F401
from modules import compliance       # noqa: F401
from modules import log_engine       # noqa: F401
from modules import threat_hunter    # noqa: F401
from modules import osint_auditor    # noqa: F401
from modules import api_tester       # noqa: F401
from modules import binary_analyzer  # noqa: F401
from modules import vault_manager    # noqa: F401
from modules import phish_awareness  # noqa: F401


def main() -> int:
    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
