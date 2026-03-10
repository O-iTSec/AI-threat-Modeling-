"""Prompt templates and LLM client for threat analysis enrichment."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a senior application security engineer performing a threat model review.
Given deterministic threat-model findings, provide augmentation only:
1. Rewrite each selected description in concise, professional security-report language.
2. Suggest concrete mitigations with priority (high/medium/low).
3. Provide an executive summary for leadership.
Do not modify deterministic fields such as severity, evidence, titles, risk scores, or IDs.
Respond strictly in JSON matching the schema provided. No markdown fences, no commentary.
"""

ANALYSIS_TEMPLATE = """\
## Threat Model Context

**Assets:** {asset_count}
**Data Flows:** {flow_count}
**Trust Boundaries:** {boundary_count}
**Preliminary Threats:** {threat_count}

### Threats to Review

{threats_json}

### Output Schema

Return ONLY valid JSON (no markdown fences) matching:
{{
  "executive_summary": "string",
  "finding_augmentations": [
    {{
      "threat_id": "string",
      "rewritten_description": "string",
      "mitigations": [
        {{
          "priority": "high | medium | low",
          "action": "string",
          "rationale": "string"
        }}
      ]
    }}
  ]
}}
"""


def load_llm_config(policy_path: Path | None = None) -> dict[str, Any]:
    """Load LLM settings from policy file, with env-var overrides."""
    defaults = {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "temperature": 0.2,
        "max_tokens": 4096,
    }
    if policy_path and policy_path.exists():
        with open(policy_path) as fh:
            policy = yaml.safe_load(fh) or {}
        defaults.update(policy.get("llm", {}))

    # Environment variables take highest precedence
    if os.environ.get("LLM_MODEL"):
        defaults["model"] = os.environ["LLM_MODEL"]
    if os.environ.get("LLM_TEMPERATURE"):
        defaults["temperature"] = float(os.environ["LLM_TEMPERATURE"])
    if os.environ.get("LLM_MAX_TOKENS"):
        defaults["max_tokens"] = int(os.environ["LLM_MAX_TOKENS"])

    return defaults


class PromptEngine:
    """Build and send prompts for LLM-based threat enrichment."""

    def __init__(
        self,
        policy_path: Path | None = None,
        api_key: str | None = None,
    ) -> None:
        self.config = load_llm_config(policy_path)
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = self.config["model"]
        self.temperature = self.config["temperature"]
        self.max_tokens = self.config["max_tokens"]

    def enrich(self, mapped_threats: dict[str, Any]) -> dict[str, Any]:
        """Send the mapped threat data to an LLM and return enriched results."""
        prompt = self._build_prompt(mapped_threats)
        trace = {
            "provider": self.config.get("provider", "openai"),
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "generated_at": datetime.now(UTC).isoformat(),
            "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        }

        if not self.api_key:
            logger.warning(
                "OPENAI_API_KEY not set — skipping LLM enrichment. "
                "Set the env var or pass api_key to PromptEngine."
            )
            return {
                "prompt_used": prompt,
                "model_metadata": trace,
                "llm_response": None,
                "raw": mapped_threats,
            }

        try:
            response_text = self._call_openai(prompt)
            parsed = self._extract_json(response_text)
            return {
                "prompt_used": prompt,
                "model_metadata": trace,
                "llm_response": parsed,
                "raw": mapped_threats,
            }
        except Exception as exc:
            logger.error("LLM enrichment failed: %s", exc)
            return {
                "prompt_used": prompt,
                "model_metadata": trace,
                "llm_response": None,
                "raw": mapped_threats,
                "llm_error": str(exc),
            }

    def _call_openai(self, prompt: str) -> str:
        from openai import OpenAI

        client = OpenAI(api_key=self.api_key)
        response = client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content

    @staticmethod
    def _extract_json(text: str) -> dict:
        """Parse JSON from the LLM response, stripping markdown fences if present."""
        cleaned = re.sub(r"```(?:json)?\s*", "", text).strip()
        cleaned = re.sub(r"```\s*$", "", cleaned).strip()
        return json.loads(cleaned)

    def _build_prompt(self, data: dict[str, Any]) -> str:
        threats = data.get("threats", [])
        return ANALYSIS_TEMPLATE.format(
            asset_count=len(threats),
            flow_count="N/A",
            boundary_count="N/A",
            threat_count=len(threats),
            threats_json=json.dumps(threats, indent=2, default=str),
        )
