"""Tests for graph export (JSON + Markdown)."""

import json
import tempfile
from pathlib import Path

from src.graph.assets import AssetGraph
from src.graph.export import GraphExporter
from src.graph.flows import FlowBuilder


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
                    "depends_on": [],
                    "networks": ["backend"],
                    "volumes": [],
                    "environment": [
                        {"key": "API_KEY", "value": "secret", "sensitive": True},
                    ],
                },
            ],
            "networks": [{"name": "frontend", "driver": "bridge"}],
            "volumes": [{"name": "data-vol", "driver": "local"}],
        }
    )
    return graph


class TestGraphExporterJSON:
    def test_valid_json_structure(self):
        graph = _build_graph()
        flows = FlowBuilder().build(graph)
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "graph.json"
            GraphExporter(source_file="test.yml").export_json(graph, flows, out)

            assert out.exists()
            with open(out) as fh:
                data = json.load(fh)

            assert "nodes" in data
            assert "edges" in data
            assert "metadata" in data
            assert data["metadata"]["node_count"] == len(data["nodes"])
            assert data["metadata"]["edge_count"] == len(data["edges"])

    def test_edges_use_id_strings(self):
        graph = _build_graph()
        flows = FlowBuilder().build(graph)
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "graph.json"
            GraphExporter().export_json(graph, flows, out)
            with open(out) as fh:
                data = json.load(fh)
            for edge in data["edges"]:
                assert isinstance(edge["source"], str)
                assert isinstance(edge["target"], str)

    def test_node_kinds_are_canonical(self):
        graph = _build_graph()
        flows = FlowBuilder().build(graph)
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "graph.json"
            GraphExporter().export_json(graph, flows, out)
            with open(out) as fh:
                data = json.load(fh)
            valid_kinds = {"service", "datastore", "external", "secret", "storage"}
            for node in data["nodes"]:
                assert node["kind"] in valid_kinds


class TestGraphExporterMarkdown:
    def test_markdown_structure(self):
        graph = _build_graph()
        flows = FlowBuilder().build(graph)
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "graph.md"
            GraphExporter(source_file="test.yml").export_markdown(graph, flows, out)

            assert out.exists()
            content = out.read_text()
            assert "# Threat Model Graph" in content
            assert "## Nodes" in content
            assert "## Edges" in content
            assert "## Summary" in content
            assert "| ID |" in content

    def test_markdown_contains_all_nodes(self):
        graph = _build_graph()
        flows = FlowBuilder().build(graph)
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "graph.md"
            GraphExporter().export_markdown(graph, flows, out)
            content = out.read_text()
            for asset in graph.all_assets():
                assert asset.id in content
