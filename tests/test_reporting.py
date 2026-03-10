"""Tests for report generation (SARIF focus — PDF requires reportlab)."""

import json
import tempfile
from pathlib import Path

from src.reporting.sarif import SARIFReporter


class TestSARIFReporter:
    def test_generates_valid_sarif(self):
        scored = {
            "threats": [
                {
                    "threat": {
                        "id": "t1",
                        "title": "Test Threat",
                        "category": "Spoofing",
                        "description": "A test threat.",
                        "affected_asset_ids": ["asset:1"],
                    },
                    "severity": "high",
                    "risk_score": 6.4,
                    "mitre": {
                        "tactics": ["Initial Access"],
                        "techniques": [
                            {
                                "id": "T1190",
                                "name": "Exploit Public-Facing Application",
                                "url": "https://attack.mitre.org/techniques/T1190/",
                            }
                        ],
                    },
                },
            ],
            "summary": {"total": 1, "by_severity": {"high": 1}, "highest_risk": 6.4},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "report.sarif"
            SARIFReporter().generate(scored, out)

            assert out.exists()
            with open(out) as fh:
                sarif = json.load(fh)
            assert sarif["version"] == "2.1.0"
            assert len(sarif["runs"]) == 1
            assert len(sarif["runs"][0]["results"]) == 1

    def test_empty_report(self):
        scored = {"threats": [], "summary": {"total": 0, "by_severity": {}, "highest_risk": 0}}
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "empty.sarif"
            SARIFReporter().generate(scored, out)
            with open(out) as fh:
                sarif = json.load(fh)
            assert sarif["runs"][0]["results"] == []
