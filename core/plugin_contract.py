"""
Contract for user plugins in plugins/.

A plugin is a Python module that defines:

  PLUGIN_NAME: str
  PLUGIN_PORTS: list[int] | "all"
  def run_check(target: str, port: int) -> dict | None

Optional:

  PLUGIN_DESCRIPTION: str
  PLUGIN_TIMEOUT: float   # seconds; the loader caps this

run_check returns None when there is nothing to report, or a dict:

  {"result": str, "severity": "info"|"warning"|"finding", "detail": str}

Plugins run in-process. Only load modules you wrote or have read.
"""

ALLOWED_SEVERITIES = ("info", "warning", "finding")
DEFAULT_TIMEOUT_SEC = 5.0
MAX_TIMEOUT_SEC = 8.0
MAX_NAME_LEN = 80
MAX_RESULT_LEN = 200
MAX_DETAIL_LEN = 500
