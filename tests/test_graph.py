"""Tests for asset graph construction and flow building."""

from src.graph.assets import AssetGraph
from src.graph.flows import FlowBuilder


def _make_compose_parsed() -> dict:
    return {
        "source": "compose",
        "services": [
            {
                "name": "web",
                "image": "nginx:1.25-alpine",
                "asset_type": "service",
                "ports": [{"host": 80, "container": 80, "protocol": "tcp"}],
                "depends_on": ["api"],
                "networks": ["frontend"],
                "volumes": [],
                "environment": [],
            },
            {
                "name": "api",
                "image": "myorg/api-server:latest",
                "asset_type": "service",
                "ports": [{"host": 8080, "container": 8080, "protocol": "tcp"}],
                "depends_on": ["db"],
                "networks": ["frontend", "backend"],
                "volumes": [],
                "environment": [
                    {"key": "JWT_SECRET", "value": "change-me", "sensitive": True},
                ],
            },
            {
                "name": "db",
                "image": "postgres:16-alpine",
                "asset_type": "datastore",
                "ports": [],
                "depends_on": [],
                "networks": ["backend"],
                "volumes": [
                    {
                        "volume": "db-data",
                        "mount_path": "/var/lib/postgresql/data",
                        "mode": "rw",
                    }
                ],
                "environment": [
                    {"key": "POSTGRES_PASSWORD", "value": "secret", "sensitive": True},
                ],
            },
        ],
        "networks": [
            {"name": "frontend", "driver": "bridge"},
            {"name": "backend", "driver": "bridge"},
        ],
        "volumes": [{"name": "db-data", "driver": "local"}],
    }


def _make_openapi_parsed() -> dict:
    return {
        "source": "openapi",
        "version": "3.0.3",
        "title": "Test API",
        "servers": ["https://api.example.com"],
        "endpoints": [
            {
                "method": "GET",
                "path": "/users",
                "operation_id": "listUsers",
                "tags": [],
                "security": [],
                "parameters": [],
                "request_body": None,
                "responses": [],
            },
        ],
        "auth_schemes": [{"name": "bearerAuth", "type": "http", "scheme": "bearer"}],
        "global_security": [],
        "schemas": [],
    }


class TestAssetGraphCompose:
    def test_node_count(self):
        graph = AssetGraph()
        graph.add_assets(_make_compose_parsed())
        # 2 services + 1 datastore + 1 storage + 2 secrets + 1 external = 7
        assert len(graph.all_assets()) == 7

    def test_node_kinds(self):
        graph = AssetGraph()
        graph.add_assets(_make_compose_parsed())
        assert len(graph.assets_by_kind("service")) == 2
        assert len(graph.assets_by_kind("datastore")) == 1
        assert len(graph.assets_by_kind("storage")) == 1
        assert len(graph.assets_by_kind("secret")) == 2
        assert len(graph.assets_by_kind("external")) == 1

    def test_datastore_classification(self):
        graph = AssetGraph()
        graph.add_assets(_make_compose_parsed())
        db = graph.get("compose:datastore:db")
        assert db is not None
        assert db.kind == "datastore"

    def test_exposed_tag(self):
        graph = AssetGraph()
        graph.add_assets(_make_compose_parsed())
        web = graph.get("compose:service:web")
        assert "exposed" in web.tags

    def test_secret_nodes_created(self):
        graph = AssetGraph()
        graph.add_assets(_make_compose_parsed())
        jwt = graph.get("compose:secret:api:JWT_SECRET")
        assert jwt is not None
        assert jwt.kind == "secret"
        assert "sensitive" in jwt.tags

    def test_to_dict(self):
        graph = AssetGraph()
        graph.add_assets(_make_compose_parsed())
        web = graph.get("compose:service:web")
        d = web.to_dict()
        assert d["id"] == "compose:service:web"
        assert d["kind"] == "service"
        assert "exposed" in d["tags"]


class TestAssetGraphOpenAPI:
    def test_creates_service_and_external(self):
        graph = AssetGraph()
        graph.add_assets(_make_openapi_parsed())
        assert len(graph.assets_by_kind("service")) == 1
        assert len(graph.assets_by_kind("external")) == 1
        api = graph.get("openapi:service:test-api")
        assert api is not None
        assert api.name == "Test API"


class TestFlowBuilder:
    def test_connects_to_from_depends_on(self):
        graph = AssetGraph()
        graph.add_assets(_make_compose_parsed())
        flows = FlowBuilder().build(graph)
        connects = [f for f in flows if f.edge_type == "connects_to"]
        pairs = [(f.source.name, f.target.name) for f in connects]
        assert ("web", "api") in pairs
        assert ("api", "db") in pairs

    def test_exposes_edges(self):
        graph = AssetGraph()
        graph.add_assets(_make_compose_parsed())
        flows = FlowBuilder().build(graph)
        exposes = [f for f in flows if f.edge_type == "exposes"]
        assert len(exposes) >= 2
        targets = [f.target.name for f in exposes]
        assert "web" in targets
        assert "api" in targets

    def test_secret_edges(self):
        graph = AssetGraph()
        graph.add_assets(_make_compose_parsed())
        flows = FlowBuilder().build(graph)
        secret_flows = [
            f for f in flows if f.edge_type == "connects_to" and f.target.kind == "secret"
        ]
        assert len(secret_flows) >= 1

    def test_storage_edges(self):
        graph = AssetGraph()
        graph.add_assets(_make_compose_parsed())
        flows = FlowBuilder().build(graph)
        storage_flows = [
            f for f in flows if f.edge_type == "connects_to" and f.source.kind == "storage"
        ]
        assert len(storage_flows) == 1
        assert storage_flows[0].target.name == "db"

    def test_calls_api_edges(self):
        graph = AssetGraph()
        graph.add_assets(_make_openapi_parsed())
        flows = FlowBuilder().build(graph)
        api_flows = [f for f in flows if f.edge_type == "calls_api"]
        assert len(api_flows) == 1
        assert api_flows[0].source.name == "API Caller"

    def test_to_dict_uses_id_strings(self):
        graph = AssetGraph()
        graph.add_assets(_make_compose_parsed())
        flows = FlowBuilder().build(graph)
        for f in flows:
            d = f.to_dict()
            assert isinstance(d["source"], str)
            assert isinstance(d["target"], str)
            assert d["edge_type"] in ("connects_to", "exposes", "calls_api")
