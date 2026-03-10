"""Tests for trust boundary detection and STRIDE analysis."""

from src.graph.assets import AssetGraph
from src.graph.flows import FlowBuilder
from src.rules.stride import STRIDE_CATEGORIES, StrideAnalyzer
from src.rules.trust_boundaries import TrustBoundaryDetector


def _build_graph():
    graph = AssetGraph()
    graph.add_assets(
        {
            "source": "compose",
            "services": [
                {
                    "name": "web",
                    "image": "nginx:alpine",
                    "asset_type": "service",
                    "ports": [{"host": 80, "container": 80, "protocol": "tcp"}],
                    "depends_on": ["api"],
                    "networks": ["frontend"],
                    "volumes": [],
                    "environment": [],
                },
                {
                    "name": "api",
                    "image": "myorg/api:latest",
                    "asset_type": "service",
                    "ports": [],
                    "depends_on": ["db"],
                    "networks": ["backend"],
                    "volumes": [],
                    "environment": [
                        {"key": "DB_PASSWORD", "value": "secret", "sensitive": True},
                    ],
                },
                {
                    "name": "db",
                    "image": "postgres:16",
                    "asset_type": "datastore",
                    "ports": [],
                    "depends_on": [],
                    "networks": ["backend"],
                    "volumes": [],
                    "environment": [],
                },
            ],
            "networks": [
                {"name": "frontend", "driver": "bridge"},
                {"name": "backend", "driver": "bridge"},
            ],
            "volumes": [],
        }
    )
    return graph


class TestTrustBoundaryDetector:
    def test_detects_network_boundaries(self):
        graph = _build_graph()
        flows = FlowBuilder().build(graph)
        boundaries = TrustBoundaryDetector().detect(graph, flows)
        boundary_names = [b.name for b in boundaries]
        assert any("frontend" in n for n in boundary_names)
        assert any("backend" in n for n in boundary_names)

    def test_detects_exposure(self):
        graph = _build_graph()
        flows = FlowBuilder().build(graph)
        boundaries = TrustBoundaryDetector().detect(graph, flows)
        assert any(b.id == "boundary:public-ingress" for b in boundaries)

    def test_detects_datastore_boundary(self):
        graph = _build_graph()
        flows = FlowBuilder().build(graph)
        boundaries = TrustBoundaryDetector().detect(graph, flows)
        assert any(b.id == "boundary:datastore" for b in boundaries)

    def test_detects_secrets_boundary(self):
        graph = _build_graph()
        flows = FlowBuilder().build(graph)
        boundaries = TrustBoundaryDetector().detect(graph, flows)
        assert any(b.id == "boundary:secrets" for b in boundaries)


class TestStrideAnalyzer:
    def test_produces_threats(self):
        graph = _build_graph()
        flows = FlowBuilder().build(graph)
        boundaries = TrustBoundaryDetector().detect(graph, flows)
        threats = StrideAnalyzer().analyze(graph, flows, boundaries)
        assert len(threats) > 0

    def test_threat_categories_are_valid(self):
        graph = _build_graph()
        flows = FlowBuilder().build(graph)
        boundaries = TrustBoundaryDetector().detect(graph, flows)
        threats = StrideAnalyzer().analyze(graph, flows, boundaries)
        for t in threats:
            assert t.category in STRIDE_CATEGORIES

    def test_threats_for_all_node_kinds(self):
        graph = _build_graph()
        flows = FlowBuilder().build(graph)
        boundaries = TrustBoundaryDetector().detect(graph, flows)
        threats = StrideAnalyzer().analyze(graph, flows, boundaries)
        affected_kinds = set()
        for t in threats:
            for aid in t.affected_asset_ids:
                asset = graph.get(aid)
                if asset:
                    affected_kinds.add(asset.kind)
        assert "service" in affected_kinds
        assert "datastore" in affected_kinds
        assert "secret" in affected_kinds
        assert "external" in affected_kinds
