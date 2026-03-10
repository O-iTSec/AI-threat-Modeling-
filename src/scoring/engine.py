"""Risk scoring and prioritisation engine."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

DEFAULT_SIGNAL_WEIGHTS = {
    "likelihood": {
        "internet_exposed": 5.0,
        "no_auth": 4.0,
        "weak_auth": 3.0,
        "privileged_container": 4.0,
        "wide_network_access": 2.0,
    },
    "impact": {
        "handles_pii": 4.0,
        "writes_to_db": 3.0,
        "admin_scope": 5.0,
        "availability_critical": 4.0,
    },
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class RiskScorer:
    """Score and rank threats using explainable likelihood/impact signals."""

    def __init__(self, policy_path: Path | None = None) -> None:
        self.policy = self._load_policy(policy_path)
        scoring_cfg = self.policy.get("scoring", {})
        policy_weights = scoring_cfg.get("weights", {})

        self.weights = {
            "likelihood": {
                **DEFAULT_SIGNAL_WEIGHTS["likelihood"],
                **policy_weights.get("likelihood", {}),
            },
            "impact": {
                **DEFAULT_SIGNAL_WEIGHTS["impact"],
                **policy_weights.get("impact", {}),
            },
        }
        self.minimum_score = float(self.policy.get("minimum_score_to_report", 0))
        self.minimum_severity = self.policy.get("minimum_severity", "info")
        self.likelihood_factor = float(scoring_cfg.get("likelihood_factor", 0.6))
        self.impact_factor = float(scoring_cfg.get("impact_factor", 0.4))

        build_cfg = self.policy.get("build", {})
        self.fail_on_score = float(build_cfg.get("fail_on_score_gte", 101))
        self.allowlist_patterns = self._compile_allowlist(build_cfg.get("allowlist_patterns", []))

    def score(self, mapped: dict[str, Any]) -> dict[str, Any]:
        threats = mapped.get("threats", [])
        scored = []
        for entry in threats:
            threat_data = entry.get("threat", entry)
            severity = self._infer_severity(threat_data)
            confidence = threat_data.get("confidence", 0.8)
            likelihood_signals = self._detect_likelihood_signals(threat_data)
            impact_signals = self._detect_impact_signals(threat_data)

            likelihood_score = self._score_signal_group(
                likelihood_signals,
                self.weights["likelihood"],
            )
            impact_score = self._score_signal_group(
                impact_signals,
                self.weights["impact"],
            )
            likelihood_max = sum(self.weights["likelihood"].values()) or 1.0
            impact_max = sum(self.weights["impact"].values()) or 1.0
            likelihood_norm = min(likelihood_score / likelihood_max, 1.0)
            impact_norm = min(impact_score / impact_max, 1.0)
            base_score = 100.0 * (
                (self.likelihood_factor * likelihood_norm) + (self.impact_factor * impact_norm)
            )
            risk_score = min(base_score * float(confidence), 100.0)

            scored.append(
                {
                    **entry,
                    "severity": severity,
                    "confidence": confidence,
                    "risk_score": round(risk_score, 2),
                    "why": {
                        "likelihood_signals": likelihood_signals,
                        "impact_signals": impact_signals,
                        "weights": {
                            "likelihood": {
                                signal: self.weights["likelihood"][signal]
                                for signal in likelihood_signals
                            },
                            "impact": {
                                signal: self.weights["impact"][signal] for signal in impact_signals
                            },
                        },
                        "formula": (
                            "score = 100 * (likelihood_factor * L_norm + "
                            "impact_factor * I_norm) * confidence"
                        ),
                        "components": {
                            "likelihood_raw": round(likelihood_score, 2),
                            "likelihood_max": round(likelihood_max, 2),
                            "impact_raw": round(impact_score, 2),
                            "impact_max": round(impact_max, 2),
                            "likelihood_norm": round(likelihood_norm, 4),
                            "impact_norm": round(impact_norm, 4),
                            "likelihood_factor": self.likelihood_factor,
                            "impact_factor": self.impact_factor,
                            "confidence": round(float(confidence), 2),
                        },
                    },
                }
            )

        scored.sort(key=lambda t: t["risk_score"], reverse=True)
        filtered = self._apply_threshold(scored)

        return {
            "threats": filtered,
            "summary": self._summarise(filtered),
        }

    def _infer_severity(self, threat: dict) -> str:
        if "severity" in threat:
            return threat["severity"]
        category = threat.get("category", "")
        category_defaults = {
            "Spoofing": "high",
            "Tampering": "high",
            "Repudiation": "medium",
            "Information Disclosure": "high",
            "Denial of Service": "medium",
            "Elevation of Privilege": "critical",
        }
        return category_defaults.get(category, "medium")

    def _apply_threshold(self, scored: list[dict]) -> list[dict]:
        filtered = [t for t in scored if t["risk_score"] >= self.minimum_score]
        cutoff = SEVERITY_ORDER.index(self.minimum_severity)
        return [t for t in filtered if SEVERITY_ORDER.index(t["severity"]) <= cutoff]

    def _summarise(self, threats: list[dict]) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for t in threats:
            sev = t["severity"]
            counts[sev] = counts.get(sev, 0) + 1
        return {
            "total": len(threats),
            "by_severity": counts,
            "highest_risk": threats[0]["risk_score"] if threats else 0,
        }

    @staticmethod
    def _load_policy(path: Path | None) -> dict[str, Any]:
        if path is None or not path.exists():
            return {}
        with open(path) as fh:
            return yaml.safe_load(fh) or {}

    def evaluate_build_gate(self, scored: dict[str, Any]) -> dict[str, Any]:
        violations = []
        for entry in scored.get("threats", []):
            if float(entry.get("risk_score", 0)) < self.fail_on_score:
                continue
            if self._is_allowlisted(entry):
                continue

            threat = entry.get("threat", entry)
            violations.append(
                {
                    "id": threat.get("id", "unknown"),
                    "title": threat.get("title", "Untitled"),
                    "risk_score": entry.get("risk_score", 0),
                }
            )

        return {
            "passed": len(violations) == 0,
            "threshold": self.fail_on_score,
            "violations": violations,
        }

    def _is_allowlisted(self, entry: dict[str, Any]) -> bool:
        if not self.allowlist_patterns:
            return False
        threat = entry.get("threat", entry)
        candidates = [
            str(threat.get("id", "")),
            str(threat.get("title", "")),
            str(threat.get("description", "")),
            " ".join(threat.get("affected_asset_ids", [])),
        ]
        return any(
            pattern.search(candidate)
            for pattern in self.allowlist_patterns
            for candidate in candidates
        )

    def _compile_allowlist(self, patterns: list[str]) -> list[re.Pattern[str]]:
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern))
            except re.error:
                continue
        return compiled

    def _score_signal_group(
        self,
        signals: list[str],
        weights: dict[str, float],
    ) -> float:
        return float(sum(weights.get(signal, 0.0) for signal in signals))

    def _detect_likelihood_signals(self, threat: dict[str, Any]) -> list[str]:
        corpus = self._build_corpus(threat)
        signals = []

        if self._contains_any(
            corpus,
            [
                "public endpoint",
                "external boundary",
                "exposed flow",
                "external:internet",
            ],
        ):
            signals.append("internet_exposed")
        if self._contains_any(
            corpus,
            [
                "without strict auth",
                "without authentication",
                "auth is absent",
                "no auth",
            ],
        ):
            signals.append("no_auth")
        if self._contains_any(
            corpus,
            [
                "weak authentication",
                "default or weak credentials",
                "credential theft",
                "brute force",
            ],
        ):
            signals.append("weak_auth")
        if self._contains_any(
            corpus,
            ["privileged container", "escape to host", "privilege escalation"],
        ):
            signals.append("privileged_container")
        if self._contains_any(
            corpus,
            ["cross-boundary", "across trust boundaries", "public_flow_targets"],
        ):
            signals.append("wide_network_access")

        return signals

    def _detect_impact_signals(self, threat: dict[str, Any]) -> list[str]:
        corpus = self._build_corpus(threat)
        category = str(threat.get("category", "")).lower()
        signals = []

        if self._contains_any(corpus, ["pii", "personal data", "sensitive data"]):
            signals.append("handles_pii")
        if self._contains_any(
            corpus,
            ["datastore", "db", "database", "unauthorised data modification"],
        ):
            signals.append("writes_to_db")
        if (
            self._contains_any(
                corpus,
                ["overprivileged", "admin", "least privilege"],
            )
            or category == "elevation of privilege"
        ):
            signals.append("admin_scope")
        if category == "denial of service" or self._contains_any(
            corpus,
            ["resource exhaustion", "denial of service", "flooded", "capacity exhaustion"],
        ):
            signals.append("availability_critical")

        return signals

    def _build_corpus(self, threat: dict[str, Any]) -> str:
        title = str(threat.get("title", ""))
        description = str(threat.get("description", ""))
        metadata = json.dumps(threat.get("metadata", {}), sort_keys=True, default=str)
        return f"{title} {description} {metadata}".lower()

    @staticmethod
    def _contains_any(corpus: str, needles: list[str]) -> bool:
        return any(needle in corpus for needle in needles)
