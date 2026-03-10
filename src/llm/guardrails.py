"""Output validation and safety checks for LLM responses."""

from __future__ import annotations

import json
from typing import Any

ALLOWED_PRIORITIES = {"high", "medium", "low"}
MAX_RESPONSE_LENGTH = 50_000


class GuardrailError(Exception):
    """Raised when an LLM response fails validation."""


class OutputGuardrail:
    """Validate, sanitise, and constrain LLM-generated threat analysis output."""

    def validate(self, llm_output: dict[str, Any]) -> dict[str, Any]:
        """Run all guardrail checks and return the validated output."""
        raw = llm_output.get("llm_response")
        if raw is None:
            return llm_output

        if isinstance(raw, str):
            raw = self._parse_json(raw)

        self._check_size(raw)
        self._check_schema(raw)
        self._check_augmentation_schema(raw)
        self._check_known_threat_ids(raw, llm_output.get("raw", {}))
        self._redact_pii(raw)

        return {**llm_output, "validated": True, "llm_response": raw}

    def _parse_json(self, text: str) -> dict:
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise GuardrailError(f"LLM output is not valid JSON: {exc}") from exc

    def _check_size(self, data: Any) -> None:
        serialised = json.dumps(data, default=str)
        if len(serialised) > MAX_RESPONSE_LENGTH:
            raise GuardrailError(
                f"LLM response exceeds {MAX_RESPONSE_LENGTH} chars ({len(serialised)} chars)."
            )

    def _check_schema(self, data: dict) -> None:
        if "finding_augmentations" not in data:
            raise GuardrailError("LLM response missing required key: 'finding_augmentations'.")

        allowed_top = {"executive_summary", "finding_augmentations"}
        unknown = set(data.keys()) - allowed_top
        if unknown:
            raise GuardrailError(f"LLM response has unsupported top-level keys: {sorted(unknown)}.")

    def _check_augmentation_schema(self, data: dict) -> None:
        augmentations = data.get("finding_augmentations", [])
        if not isinstance(augmentations, list):
            raise GuardrailError("'finding_augmentations' must be a list.")

        executive_summary = data.get("executive_summary", "")
        if executive_summary and not isinstance(executive_summary, str):
            raise GuardrailError("'executive_summary' must be a string.")
        if isinstance(executive_summary, str) and len(executive_summary) > 4000:
            raise GuardrailError("'executive_summary' exceeds 4000 characters.")

        for item in augmentations:
            if not isinstance(item, dict):
                raise GuardrailError("Each finding augmentation must be an object.")
            allowed_keys = {"threat_id", "rewritten_description", "mitigations"}
            unknown = set(item.keys()) - allowed_keys
            if unknown:
                raise GuardrailError(
                    f"Finding augmentation has unsupported keys: {sorted(unknown)}."
                )

            threat_id = item.get("threat_id")
            if not isinstance(threat_id, str) or not threat_id.strip():
                raise GuardrailError("Each finding augmentation requires a non-empty 'threat_id'.")

            rewritten = item.get("rewritten_description", "")
            if rewritten and (not isinstance(rewritten, str) or len(rewritten) > 2000):
                raise GuardrailError("'rewritten_description' must be a string <= 2000 characters.")

            mitigations = item.get("mitigations", [])
            if mitigations and not isinstance(mitigations, list):
                raise GuardrailError("'mitigations' must be a list.")
            if isinstance(mitigations, list) and len(mitigations) > 10:
                raise GuardrailError("Each finding may include at most 10 mitigations.")

            for mitigation in mitigations:
                if not isinstance(mitigation, dict):
                    raise GuardrailError("Each mitigation entry must be an object.")
                allowed_mitigation_keys = {"priority", "action", "rationale"}
                unknown_m = set(mitigation.keys()) - allowed_mitigation_keys
                if unknown_m:
                    raise GuardrailError(f"Mitigation has unsupported keys: {sorted(unknown_m)}.")
                priority = str(mitigation.get("priority", "")).lower()
                if priority not in ALLOWED_PRIORITIES:
                    raise GuardrailError(
                        f"Invalid mitigation priority '{priority}'. "
                        f"Expected one of {sorted(ALLOWED_PRIORITIES)}."
                    )
                if not str(mitigation.get("action", "")).strip():
                    raise GuardrailError("Mitigation 'action' must be non-empty.")
                if not str(mitigation.get("rationale", "")).strip():
                    raise GuardrailError("Mitigation 'rationale' must be non-empty.")

    def _check_known_threat_ids(self, data: dict, raw_payload: dict[str, Any]) -> None:
        known_ids = set()
        for entry in raw_payload.get("threats", []):
            threat = entry.get("threat", entry)
            tid = threat.get("id")
            if tid:
                known_ids.add(tid)

        for item in data.get("finding_augmentations", []):
            tid = item.get("threat_id")
            if tid and tid not in known_ids:
                raise GuardrailError(f"Unknown threat_id '{tid}' in finding augmentation.")

    def _redact_pii(self, data: dict) -> None:
        """Placeholder for PII/secret redaction in LLM outputs."""
        pass
