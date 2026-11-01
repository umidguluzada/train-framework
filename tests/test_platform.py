"""Offline tests for the TRAIN platform layer."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.async_http import MAX_CONCURRENCY, AsyncHttpClient
from core.bridge import BridgeError, run_port_scan, validate_scan_result
from core.findings import collect_report
from core.tui_engine import Session
from modules.compliance import ComplianceCheck, ComplianceReport
from modules.plugin_engine import discover_plugins, run_plugins_for_port
from modules.report_generator import _build_pdf_report, build_html_report, write_json_report
from templates.parser import TemplateError, load_template

ROOT = Path(__file__).resolve().parent.parent


class AsyncHttpTests(unittest.TestCase):
    def test_concurrency_is_capped(self) -> None:
        client = AsyncHttpClient(concurrency=500)
        self.assertEqual(client.concurrency, MAX_CONCURRENCY)
        self.assertLessEqual(AsyncHttpClient(concurrency=0).concurrency, MAX_CONCURRENCY)

    def test_timeout_is_capped(self) -> None:
        client = AsyncHttpClient(timeout_total=120)
        self.assertLessEqual(client.timeout_total, 30)


class ScanContractTests(unittest.TestCase):
    def test_invalid_rows_are_dropped(self) -> None:
        result = validate_scan_result({
            "target": "127.0.0.1",
            "open_ports": [
                {"port": 22, "service_guess": "ssh", "banner": "SSH-2.0"},
                {"port": "nope"},
                {"port": 70000, "service_guess": "odd"},
                "not-a-row",
            ],
        })
        self.assertEqual(len(result["open_ports"]), 1)
        self.assertEqual(result["open_ports"][0]["port"], 22)

    def test_reversed_range_is_rejected_before_launch(self) -> None:
        with self.assertRaises(BridgeError):
            run_port_scan("127.0.0.1", 80, 1)


class TemplateTests(unittest.TestCase):
    def test_example_template_loads(self) -> None:
        data = load_template(ROOT / "templates" / "example-template.yaml")
        self.assertEqual(data["id"], "security-header-baseline")
        self.assertEqual({check["type"] for check in data["checks"]}, {"http-path", "http-header"})

    def test_unknown_check_type_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text(
                "id: x\nname: bad\nchecks:\n  - type: raw-request\n    name: nope\n    path: /\n",
                encoding="utf-8",
            )
            with self.assertRaises(TemplateError):
                load_template(path)

    def test_parent_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text(
                "id: x\nname: bad\nchecks:\n"
                "  - type: http-path\n    name: traversal\n    path: /../secret\n    expect_status: 200\n",
                encoding="utf-8",
            )
            with self.assertRaises(TemplateError):
                load_template(path)


class PluginTests(unittest.TestCase):
    def test_loader_accepts_contract_and_records_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "good.py").write_text(
                "PLUGIN_NAME = 'Demo'\n"
                "PLUGIN_DESCRIPTION = 'A demo check'\n"
                "PLUGIN_PORTS = [80]\n"
                "def run_check(target, port):\n"
                "    return {'result': 'ok', 'severity': 'critical', 'detail': 'd'}\n",
                encoding="utf-8",
            )
            (directory / "broken.py").write_text("PLUGIN_NAME = 'missing the rest'\n", encoding="utf-8")
            plugins, errors = discover_plugins(directory, use_cache=False)
            self.assertEqual(len(plugins), 1)
            self.assertEqual(plugins[0].description, "A demo check")
            self.assertTrue(errors)

            results = run_plugins_for_port("example.test", 80, directory)
            self.assertEqual(results[0]["severity"], "info")
            self.assertEqual(results[0]["_plugin_name"], "Demo")

    def test_plugin_timeout_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "slow.py").write_text(
                "import time\n"
                "PLUGIN_NAME = 'Slow'\n"
                "PLUGIN_PORTS = [9]\n"
                "PLUGIN_TIMEOUT = 0.2\n"
                "def run_check(target, port):\n"
                "    time.sleep(0.6)\n"
                "    return {'result': 'late', 'severity': 'info', 'detail': ''}\n",
                encoding="utf-8",
            )
            results = run_plugins_for_port("example.test", 9, directory)
            self.assertEqual(results[0]["result"], "timeout")


class ReportTests(unittest.TestCase):
    def test_json_html_and_pdf_share_one_finding(self) -> None:
        session = Session(target="127.0.0.1")
        session.state["last_compliance_report"] = ComplianceReport(checks=[
            ComplianceCheck("SSH-1", "SSH root login disabled", "fail", "PermitRootLogin yes"),
        ])
        document = collect_report(session)
        self.assertEqual(document.risk["high"], 1)
        self.assertEqual(document.risk["level"], "MEDIUM")

        html = build_html_report(session)
        self.assertIn("finding-filter", html)
        self.assertIn("SSH root login disabled", html)
        self.assertIn("data-sev=\"high\"", html)

        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "train_report.json"
            pdf_path = Path(tmp) / "train_report.pdf"
            write_json_report(session, json_path)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["findings"][0]["source"], "compliance")
            self.assertEqual(payload["version"], "1.0.0")
            _build_pdf_report(session, pdf_path)
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
