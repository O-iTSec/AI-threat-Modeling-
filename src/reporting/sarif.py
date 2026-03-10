"""SARIF (Static Analysis Results Interchange Format) report generation.

Produces SARIF v2.1.0 output for integration with GitHub Code Scanning,
VS Code SARIF Viewer, and other DevSecOps tools.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class SARIFReporter:
    """Generate a SARIF v2.1.0 threat model report."""

    def generate(self, scored: dict[str, Any], output_path: Path) -> Path:
        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [self._build_run(scored)],
        }
        with open(output_path, "w") as fh:
            json.dump(sarif, fh, indent=2, default=str)
        return output_path

    def _build_run(self, scored: dict[str, Any]) -> dict[str, Any]:
        rules = []
        results = []

        for idx, entry in enumerate(scored.get("threats", [])):
            threat = entry.get("threat", entry)
            rule_id = threat.get("id", f"TM{idx:04d}")
            severity = entry.get("severity", "info")
            mitre = entry.get("mitre", {})

            rules.append(self._build_rule(rule_id, threat, severity, mitre))
            results.append(self._build_result(rule_id, threat, severity, entry))

        return {
            "tool": {
                "driver": {
                    "name": "ai-threat-model",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/your-org/ai-threat-model",
                    "rules": rules,
                },
            },
            "results": results,
        }

    def _build_rule(
        self,
        rule_id: str,
        threat: dict,
        severity: str,
        mitre: dict,
    ) -> dict[str, Any]:
        help_text = threat.get("description", "")
        techniques = mitre.get("techniques", [])
        if techniques:
            help_text += "\n\nMITRE ATT&CK: " + ", ".join(
                f"{t['id']} ({t['name']})" for t in techniques
            )

        return {
            "id": rule_id,
            "name": threat.get("title", "Unnamed Threat"),
            "shortDescription": {"text": threat.get("title", "")},
            "fullDescription": {"text": threat.get("description", "")},
            "helpUri": techniques[0]["url"] if techniques else "",
            "help": {"text": help_text, "markdown": help_text},
            "defaultConfiguration": {
                "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "note"),
            },
            "properties": {
                "tags": [threat.get("category", ""), "security", "threat-model"],
            },
        }

    def _build_result(
        self,
        rule_id: str,
        threat: dict,
        severity: str,
        entry: dict,
    ) -> dict[str, Any]:
        return {
            "ruleId": rule_id,
            "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "note"),
            "message": {"text": threat.get("description", "")},
            "properties": {
                "risk_score": entry.get("risk_score", 0),
                "affected_assets": threat.get("affected_asset_ids", []),
            },
        }
