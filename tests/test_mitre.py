"""Tests for MITRE ATT&CK mapping."""

from src.mitre.mapping import MitreMapper
from src.rules.stride import Threat


class TestMitreMapper:
    def test_maps_spoofing_to_initial_access(self):
        threats = [
            Threat(
                id="test:1",
                category="Spoofing",
                title="Test spoofing threat",
                description="A test.",
            )
        ]
        result = MitreMapper().map(threats)
        assert len(result["threats"]) == 1
        entry = result["threats"][0]
        assert "Initial Access" in entry["mitre"]["tactics"]
        assert len(entry["mitre"]["techniques"]) > 0
        assert all("rationale" in t for t in entry["mitre"]["techniques"])

    def test_maps_elevation_to_priv_esc(self):
        threats = [
            Threat(
                id="test:2",
                category="Elevation of Privilege",
                title="Test EoP",
                description="A test.",
            )
        ]
        result = MitreMapper().map(threats)
        entry = result["threats"][0]
        assert "Privilege Escalation" in entry["mitre"]["tactics"]

    def test_empty_threats(self):
        result = MitreMapper().map([])
        assert result["threats"] == []

    def test_maps_public_endpoint_to_exploit_with_rationale(self):
        threats = [
            Threat(
                id="test:3",
                category="Spoofing",
                title="Public endpoint without strict auth/rate controls",
                description="Public endpoint on api is reachable from an external boundary.",
            )
        ]
        result = MitreMapper().map(threats)
        techniques = result["threats"][0]["mitre"]["techniques"]
        ids = {t["id"] for t in techniques}
        assert "T1190" in ids
        assert "T1110" in ids
        assert all(t.get("rationale") for t in techniques)
