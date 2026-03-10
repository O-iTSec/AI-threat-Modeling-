"""Map STRIDE threats to MITRE ATT&CK techniques."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.rules.stride import Threat

_DATASET_PATH = Path(__file__).parent / "data" / "techniques.json"

# STRIDE → ATT&CK tactic mapping (default associations)
_STRIDE_TO_TACTIC: dict[str, list[str]] = {
    "Spoofing": ["Initial Access", "Credential Access"],
    "Tampering": ["Persistence", "Defense Evasion"],
    "Repudiation": ["Defense Evasion"],
    "Information Disclosure": ["Collection", "Exfiltration"],
    "Denial of Service": ["Impact"],
    "Elevation of Privilege": ["Privilege Escalation"],
}

_CATEGORY_FALLBACK_TECHNIQUES: dict[str, list[str]] = {
    "Spoofing": ["T1078", "T1110"],
    "Tampering": ["T1562", "T1070"],
    "Repudiation": ["T1070"],
    "Information Disclosure": ["T1005", "T1041"],
    "Denial of Service": ["T1498", "T1499"],
    "Elevation of Privilege": ["T1548", "T1068"],
}

_MAPPING_RULES: list[dict[str, Any]] = [
    {
        "name": "public-endpoint-auth",
        "title_contains": ["Public endpoint without strict auth/rate controls"],
        "description_contains": ["external boundary", "authentication"],
        "techniques": ["T1190", "T1110", "T1078"],
        "rationale": (
            "Publicly reachable endpoint with weak auth/rate controls can "
            "enable exploitation and password attacks."
        ),
    },
    {
        "name": "public-endpoint-disclosure",
        "title_contains": ["Public endpoint may leak sensitive data"],
        "description_contains": ["Public endpoint", "sensitive response data"],
        "techniques": ["T1005", "T1041"],
        "rationale": (
            "Sensitive data exposed by a public endpoint can be collected and exfiltrated."
        ),
    },
    {
        "name": "credential-weakness",
        "title_contains": [
            "Default or weak credentials",
            "Credential theft enables impersonation",
        ],
        "description_contains": [
            "default or weak authentication credentials",
            "allows an attacker to impersonate",
        ],
        "techniques": ["T1552", "T1110", "T1078"],
        "rationale": (
            "Weak or stolen credentials map to credential access and account misuse activity."
        ),
    },
    {
        "name": "secret-exposure",
        "title_contains": ["Secret exposure in environment"],
        "description_contains": ["process listing", "logs", "crash dumps"],
        "techniques": ["T1552", "T1005"],
        "rationale": (
            "Exposed secrets in runtime environments are unsecured "
            "credentials that can be harvested."
        ),
    },
    {
        "name": "overprivileged-secret",
        "title_contains": ["Overprivileged secret scope"],
        "description_contains": ["least privilege", "broader access"],
        "techniques": ["T1548", "T1068"],
        "rationale": (
            "Overprivileged credentials can be abused to elevate privileges beyond intended scope."
        ),
    },
    {
        "name": "encryption-gap",
        "title_contains": ["Unencrypted data at rest", "Unencrypted persistent volume"],
        "description_contains": ["without encryption", "encryption at rest"],
        "techniques": ["T1005", "T1530", "T1041"],
        "rationale": (
            "Unencrypted stored data can be collected from local/cloud stores and exfiltrated."
        ),
    },
    {
        "name": "dos-flooding",
        "title_contains": ["Publicly exposed flow can be flooded", "Resource exhaustion"],
        "description_contains": ["resource exhaustion", "flooded"],
        "techniques": ["T1498", "T1499"],
        "rationale": (
            "Exposed services without upstream limits are susceptible to "
            "network and endpoint DoS activity."
        ),
    },
]


class MitreMapper:
    """Enrich threats with matching MITRE ATT&CK technique references."""

    def __init__(self, dataset_path: Path | None = None) -> None:
        self._dataset = self._load(dataset_path or _DATASET_PATH)
        self._dataset_by_id = {tech["id"]: tech for tech in self._dataset}

    def map(self, threats: list[Threat] | Any) -> dict[str, Any]:
        if isinstance(threats, dict):
            threat_list = threats.get("threats", threats)
        else:
            threat_list = threats

        enriched = []
        for threat in threat_list:
            threat_data = threat if isinstance(threat, dict) else threat.__dict__
            category = threat_data.get("category", "")
            tactics = _STRIDE_TO_TACTIC.get(category, [])
            techniques = self._map_techniques_with_rationale(threat_data, category)
            enriched.append(
                {
                    "threat": threat_data,
                    "mitre": {
                        "tactics": tactics,
                        "techniques": techniques,
                    },
                }
            )

        return {"threats": enriched}

    def _map_techniques_with_rationale(
        self,
        threat: dict[str, Any],
        category: str,
    ) -> list[dict[str, str]]:
        matches = self._apply_rules(threat)
        if not matches:
            matches = [
                (
                    tid,
                    f"Fallback mapping from STRIDE category '{category}' to ATT&CK technique.",
                )
                for tid in _CATEGORY_FALLBACK_TECHNIQUES.get(category, [])
            ]

        deduped: dict[str, str] = {}
        for technique_id, rationale in matches:
            if technique_id in self._dataset_by_id and technique_id not in deduped:
                deduped[technique_id] = rationale

        resolved = []
        for technique_id in sorted(deduped):
            technique = self._dataset_by_id[technique_id]
            resolved.append(
                {
                    "id": technique["id"],
                    "name": technique["name"],
                    "url": technique.get("url", ""),
                    "rationale": deduped[technique_id],
                }
            )
        return resolved

    def _apply_rules(self, threat: dict[str, Any]) -> list[tuple[str, str]]:
        title = (threat.get("title") or "").lower()
        description = (threat.get("description") or "").lower()
        results: list[tuple[str, str]] = []

        for rule in _MAPPING_RULES:
            title_needles = [needle.lower() for needle in rule.get("title_contains", [])]
            desc_needles = [needle.lower() for needle in rule.get("description_contains", [])]
            title_match = any(needle in title for needle in title_needles)
            desc_match = any(needle in description for needle in desc_needles)
            if not (title_match or desc_match):
                continue

            rationale = rule["rationale"]
            for technique_id in rule["techniques"]:
                results.append((technique_id, rationale))

        return results

    @staticmethod
    def _load(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        with open(path) as fh:
            return json.load(fh)
