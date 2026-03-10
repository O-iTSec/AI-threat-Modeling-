"""Tests for LLM prompt engine and guardrails."""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.llm.guardrails import GuardrailError, OutputGuardrail
from src.llm.prompts import PromptEngine, load_llm_config


class TestLoadLLMConfig:
    def test_defaults_without_policy(self):
        cfg = load_llm_config(None)
        assert cfg["model"] == "gpt-4o-mini"
        assert cfg["temperature"] == 0.2
        assert cfg["max_tokens"] == 4096

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("LLM_MODEL", "gpt-3.5-turbo")
        monkeypatch.setenv("LLM_TEMPERATURE", "0.5")
        cfg = load_llm_config(None)
        assert cfg["model"] == "gpt-3.5-turbo"
        assert cfg["temperature"] == 0.5


class TestPromptEngine:
    def test_skips_when_no_api_key(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        engine = PromptEngine(api_key=None)
        result = engine.enrich({"threats": []})
        assert result["llm_response"] is None
        assert "prompt_used" in result

    def test_prompt_contains_threat_count(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        engine = PromptEngine(api_key=None)
        result = engine.enrich({"threats": [{"id": "t1"}, {"id": "t2"}]})
        assert "2" in result["prompt_used"]

    def test_live_call_returns_parsed_response(self, monkeypatch):
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(
            {
                "executive_summary": "Top risks are internet-exposed paths and weak credentials.",
                "finding_augmentations": [
                    {
                        "threat_id": "t1",
                        "rewritten_description": (
                            "The endpoint is reachable from the internet with weak controls."
                        ),
                        "mitigations": [
                            {
                                "priority": "high",
                                "action": "Enforce MFA and lockout policies.",
                                "rationale": "Reduces credential-stuffing risk.",
                            }
                        ],
                    }
                ],
            }
        )

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_client):
            engine = PromptEngine(api_key="sk-test-key")
            result = engine.enrich({"threats": [{"threat": {"id": "t1"}}]})

        assert result["llm_response"] is not None
        assert result["llm_response"]["finding_augmentations"][0]["threat_id"] == "t1"
        assert "model_metadata" in result
        mock_client.chat.completions.create.assert_called_once()

    def test_handles_api_error_gracefully(self, monkeypatch):
        with patch("openai.OpenAI") as mock_cls:
            mock_cls.return_value.chat.completions.create.side_effect = RuntimeError(
                "API rate limit"
            )
            engine = PromptEngine(api_key="sk-test-key")
            result = engine.enrich({"threats": []})

        assert result["llm_response"] is None
        assert "API rate limit" in result["llm_error"]

    def test_strips_markdown_fences(self):
        engine = PromptEngine(api_key=None)
        text = '```json\n{"executive_summary": "ok", "finding_augmentations": []}\n```'
        parsed = engine._extract_json(text)
        assert "finding_augmentations" in parsed


class TestOutputGuardrail:
    def test_passthrough_when_no_llm_response(self):
        guardrail = OutputGuardrail()
        data = {"llm_response": None, "raw": {}}
        result = guardrail.validate(data)
        assert result["llm_response"] is None

    def test_rejects_invalid_json_string(self):
        guardrail = OutputGuardrail()
        data = {"llm_response": "not valid json"}
        with pytest.raises(GuardrailError, match="not valid JSON"):
            guardrail.validate(data)

    def test_rejects_invalid_severity(self):
        guardrail = OutputGuardrail()
        data = {
            "llm_response": {
                "finding_augmentations": [
                    {
                        "threat_id": "t1",
                        "rewritten_description": "desc",
                        "mitigations": [
                            {
                                "priority": "urgent",
                                "action": "do x",
                                "rationale": "because",
                            }
                        ],
                    }
                ],
            },
            "raw": {"threats": [{"threat": {"id": "t1"}}]},
        }
        with pytest.raises(GuardrailError, match="Invalid mitigation priority"):
            guardrail.validate(data)

    def test_rejects_unknown_threat_id(self):
        guardrail = OutputGuardrail()
        data = {
            "llm_response": {
                "finding_augmentations": [
                    {
                        "threat_id": "missing",
                        "rewritten_description": "desc",
                        "mitigations": [
                            {
                                "priority": "high",
                                "action": "do x",
                                "rationale": "because",
                            }
                        ],
                    }
                ],
            },
            "raw": {"threats": [{"threat": {"id": "t1"}}]},
        }
        with pytest.raises(GuardrailError, match="Unknown threat_id"):
            guardrail.validate(data)

    def test_accepts_valid_response(self):
        guardrail = OutputGuardrail()
        data = {
            "llm_response": {
                "executive_summary": "Most risks stem from exposed interfaces.",
                "finding_augmentations": [
                    {
                        "threat_id": "t1",
                        "rewritten_description": "Public endpoint lacks strict access controls.",
                        "mitigations": [
                            {
                                "priority": "high",
                                "action": "Require strong authentication for public endpoints.",
                                "rationale": "Prevents unauthorized initial access.",
                            }
                        ],
                    }
                ],
            },
            "raw": {"threats": [{"threat": {"id": "t1"}}]},
        }
        result = guardrail.validate(data)
        assert result["validated"] is True
