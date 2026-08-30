#!/usr/bin/env python3
"""
TRAIN Framework - Threat Response & Automated Intelligence Network
Entry point.
"""

import sys

from core.tui_engine import run
from core import bridge
from modules import web_auditor
from modules import crypto_utils
from modules import pass_auditor
from modules import script_engine
from modules import cve_lookup
from modules import compliance
from modules import log_engine
from modules import threat_hunter
from modules import osint_auditor
from modules import api_tester
from modules import binary_analyzer
from modules import vault_manager
from modules import phish_awareness
from modules import dir_brute
from modules import report_generator


def main() -> int:
    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
