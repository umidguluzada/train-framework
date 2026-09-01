#!/usr/bin/env python3
"""
TRAIN Framework - Threat Response & Automated Intelligence Network
Entry point.

Each module registers its commands into core.tui_engine.COMMAND_REGISTRY via
the `register_command` decorator. Importing a module here (for its side
effect) is enough to make its commands available in the TUI.
"""

import sys

from core.tui_engine import run
from core import bridge              # noqa: F401  -> registers "scan", "sniff", "ids-run"
from modules import web_auditor      # noqa: F401  -> registers "audit-web", "web-proxy"
from modules import crypto_utils     # noqa: F401  -> registers "encode"/"decode"/"hash"
from modules import pass_auditor     # noqa: F401  -> registers "audit-pass"
from modules import script_engine    # noqa: F401  -> registers "run-tse"
from modules import cve_lookup       # noqa: F401  -> registers "audit-cve", "template-scan"
from modules import compliance       # noqa: F401  -> registers "audit-compliance"
from modules import log_engine       # noqa: F401  -> registers "audit-logs"
from modules import threat_hunter    # noqa: F401  -> registers "hunt-mitre", "hunt-beacon"
from modules import osint_auditor    # noqa: F401  -> registers "audit-osint", "geo-track", "check-vt"
from modules import api_tester       # noqa: F401  -> registers "api-test", "api-discover"
from modules import binary_analyzer  # noqa: F401  -> registers "analyze-binary"
from modules import vault_manager    # noqa: F401  -> registers "vault-*"
from modules import phish_awareness  # noqa: F401  -> registers "phish-awareness", "phish-quiz"
from modules import dir_brute        # noqa: F401  -> registers "dir-brute"
from modules import report_generator  # noqa: F401  -> registers "generate-report"
from modules import wifi_audit        # noqa: F401  -> registers "wifi-scan", "router-audit"


def main() -> int:
    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
