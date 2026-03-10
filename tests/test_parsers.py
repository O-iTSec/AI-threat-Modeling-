"""Tests for infrastructure and API parsers."""

from pathlib import Path

from src.parsers.compose import ComposeParser
from src.parsers.k8s import K8sParser
from src.parsers.openapi import OpenAPIParser

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


class TestComposeParser:
    def test_parse_returns_services(self):
        result = ComposeParser().parse(EXAMPLES / "docker-compose.yml")
        assert result["source"] == "compose"
        names = [s["name"] for s in result["services"]]
        assert "web" in names
        assert "api" in names
        assert "db" in names

    def test_service_classification(self):
        result = ComposeParser().parse(EXAMPLES / "docker-compose.yml")
        by_name = {s["name"]: s for s in result["services"]}
        assert by_name["web"]["asset_type"] == "service"
        assert by_name["api"]["asset_type"] == "service"
        assert by_name["db"]["asset_type"] == "datastore"
        assert by_name["cache"]["asset_type"] == "datastore"

    def test_structured_ports(self):
        result = ComposeParser().parse(EXAMPLES / "docker-compose.yml")
        web = next(s for s in result["services"] if s["name"] == "web")
        assert len(web["ports"]) == 2
        assert web["ports"][0] == {"host": 80, "container": 80, "protocol": "tcp"}
        assert web["ports"][1] == {"host": 443, "container": 443, "protocol": "tcp"}

    def test_sensitive_env_vars(self):
        result = ComposeParser().parse(EXAMPLES / "docker-compose.yml")
        api = next(s for s in result["services"] if s["name"] == "api")
        env_map = {e["key"]: e for e in api["environment"]}
        assert env_map["JWT_SECRET"]["sensitive"] is True
        assert env_map["DATABASE_URL"]["sensitive"] is False

    def test_volume_mount_parsing(self):
        result = ComposeParser().parse(EXAMPLES / "docker-compose.yml")
        db = next(s for s in result["services"] if s["name"] == "db")
        assert len(db["volumes"]) == 1
        assert db["volumes"][0]["volume"] == "db-data"
        assert db["volumes"][0]["mount_path"] == "/var/lib/postgresql/data"

    def test_parse_extracts_networks(self):
        result = ComposeParser().parse(EXAMPLES / "docker-compose.yml")
        net_names = [n["name"] for n in result["networks"]]
        assert "frontend" in net_names
        assert "backend" in net_names

    def test_parse_extracts_volumes(self):
        result = ComposeParser().parse(EXAMPLES / "docker-compose.yml")
        vol_names = [v["name"] for v in result["volumes"]]
        assert "db-data" in vol_names


class TestK8sParser:
    def test_parse_multi_doc(self):
        result = K8sParser().parse(EXAMPLES / "k8s-deployment.yaml")
        assert result["source"] == "k8s"
        kinds = [r["kind"] for r in result["resources"]]
        assert "Deployment" in kinds
        assert "Service" in kinds
        assert "Ingress" in kinds

    def test_deployment_has_containers(self):
        result = K8sParser().parse(EXAMPLES / "k8s-deployment.yaml")
        deployment = next(r for r in result["resources"] if r["kind"] == "Deployment")
        containers = deployment["spec_summary"]["containers"]
        assert len(containers) >= 1
        assert containers[0]["image"] == "myorg/api-server:v2.1.0"


class TestOpenAPIParser:
    def test_parse_endpoints(self):
        result = OpenAPIParser().parse(EXAMPLES / "openapi-spec.yaml")
        assert result["source"] == "openapi"
        paths = [ep["path"] for ep in result["endpoints"]]
        assert "/users" in paths
        assert "/admin/config" in paths

    def test_parse_auth_schemes(self):
        result = OpenAPIParser().parse(EXAMPLES / "openapi-spec.yaml")
        scheme_names = [s["name"] for s in result["auth_schemes"]]
        assert "bearerAuth" in scheme_names

    def test_auth_scheme_detail(self):
        result = OpenAPIParser().parse(EXAMPLES / "openapi-spec.yaml")
        bearer = next(s for s in result["auth_schemes"] if s["name"] == "bearerAuth")
        assert bearer["type"] == "http"
        assert bearer["scheme"] == "bearer"
        assert bearer["bearer_format"] == "JWT"

    def test_request_body_extraction(self):
        result = OpenAPIParser().parse(EXAMPLES / "openapi-spec.yaml")
        create_user = next(ep for ep in result["endpoints"] if ep["operation_id"] == "createUser")
        assert create_user["request_body"] is not None
        assert create_user["request_body"]["required"] is True
        assert create_user["request_body"]["schema_ref"] == "#/components/schemas/User"

    def test_response_extraction(self):
        result = OpenAPIParser().parse(EXAMPLES / "openapi-spec.yaml")
        create_user = next(ep for ep in result["endpoints"] if ep["operation_id"] == "createUser")
        statuses = [r["status"] for r in create_user["responses"]]
        assert "201" in statuses

    def test_parameter_detail(self):
        result = OpenAPIParser().parse(EXAMPLES / "openapi-spec.yaml")
        get_user = next(ep for ep in result["endpoints"] if ep["operation_id"] == "getUser")
        id_param = next(p for p in get_user["parameters"] if p["name"] == "id")
        assert id_param["in"] == "path"
        assert id_param["required"] is True

    def test_schema_properties(self):
        result = OpenAPIParser().parse(EXAMPLES / "openapi-spec.yaml")
        user_schema = next(s for s in result["schemas"] if s["name"] == "User")
        prop_names = [p["name"] for p in user_schema["properties"]]
        assert "id" in prop_names
        assert "email" in prop_names
        assert "role" in prop_names
        email_prop = next(p for p in user_schema["properties"] if p["name"] == "email")
        assert email_prop["format"] == "email"

    def test_no_request_body_for_get(self):
        result = OpenAPIParser().parse(EXAMPLES / "openapi-spec.yaml")
        list_users = next(ep for ep in result["endpoints"] if ep["operation_id"] == "listUsers")
        assert list_users["request_body"] is None
