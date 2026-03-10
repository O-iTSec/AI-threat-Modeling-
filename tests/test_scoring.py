"""Tests for risk scoring engine."""

from pathlib import Path

from src.scoring.engine import RiskScorer


class TestRiskScorer:
    def test_scores_are_sorted_descending(self):
        scorer = RiskScorer()
        data = {
            "threats": [
                {"threat": {"id": "t1", "category": "Denial of Service", "title": "DoS"}},
                {"threat": {"id": "t2", "category": "Elevation of Privilege", "title": "EoP"}},
                {"threat": {"id": "t3", "category": "Repudiation", "title": "Rep"}},
            ]
        }
        result = scorer.score(data)
        scores = [t["risk_score"] for t in result["threats"]]
        assert scores == sorted(scores, reverse=True)

    def test_summary_counts(self):
        scorer = RiskScorer()
        data = {
            "threats": [
                {"threat": {"id": "t1", "category": "Spoofing", "title": "S1"}},
                {"threat": {"id": "t2", "category": "Spoofing", "title": "S2"}},
            ]
        }
        result = scorer.score(data)
        assert result["summary"]["total"] == 2

    def test_empty_threats(self):
        scorer = RiskScorer()
        result = scorer.score({"threats": []})
        assert result["summary"]["total"] == 0
        assert result["summary"]["highest_risk"] == 0

    def test_score_has_why_breakdown(self):
        scorer = RiskScorer()
        data = {
            "threats": [
                {
                    "threat": {
                        "id": "t1",
                        "category": "Spoofing",
                        "title": "Public endpoint without strict auth/rate controls",
                        "description": "Public endpoint reachable from external boundary.",
                    }
                }
            ]
        }
        result = scorer.score(data)
        why = result["threats"][0]["why"]
        assert "likelihood_signals" in why
        assert "impact_signals" in why
        assert "weights" in why
        assert "components" in why

    def test_build_gate_fails_without_allowlist(self, tmp_path: Path):
        policy = tmp_path / "strict.yml"
        policy.write_text(
            "minimum_score_to_report: 0\nbuild:\n  fail_on_score_gte: 1\n  allowlist_patterns: []\n"
        )
        scorer = RiskScorer(policy_path=policy)
        scored = scorer.score(
            {
                "threats": [
                    {
                        "threat": {
                            "id": "threat:1",
                            "category": "Spoofing",
                            "title": "Public endpoint without strict auth/rate controls",
                            "description": "Public endpoint reachable from external boundary.",
                        }
                    }
                ]
            }
        )
        gate = scorer.evaluate_build_gate(scored)
        assert gate["passed"] is False
        assert len(gate["violations"]) == 1

    def test_build_gate_passes_with_allowlist(self, tmp_path: Path):
        policy = tmp_path / "allowlisted.yml"
        policy.write_text(
            "minimum_score_to_report: 0\n"
            "build:\n"
            "  fail_on_score_gte: 1\n"
            "  allowlist_patterns:\n"
            "    - '^threat:1$'\n"
        )
        scorer = RiskScorer(policy_path=policy)
        scored = scorer.score(
            {
                "threats": [
                    {
                        "threat": {
                            "id": "threat:1",
                            "category": "Spoofing",
                            "title": "Public endpoint without strict auth/rate controls",
                            "description": "Public endpoint reachable from external boundary.",
                        }
                    }
                ]
            }
        )
        gate = scorer.evaluate_build_gate(scored)
        assert gate["passed"] is True
