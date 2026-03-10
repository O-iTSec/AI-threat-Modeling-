"""Parser for OpenAPI / Swagger specifications."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class OpenAPIParser:
    """Extract endpoints, auth schemes, request/response schemas from OpenAPI specs."""

    def parse(self, path: Path) -> dict[str, Any]:
        with open(path) as fh:
            raw = yaml.safe_load(fh)

        version = raw.get("openapi") or raw.get("swagger", "unknown")
        info = raw.get("info", {})
        endpoints = self._extract_endpoints(raw.get("paths", {}))
        auth = self._extract_security(raw)
        global_security = raw.get("security", [])
        schemas = self._extract_schemas(raw)

        return {
            "source": "openapi",
            "version": version,
            "title": info.get("title", "Untitled"),
            "servers": [s.get("url", "") for s in raw.get("servers", [])],
            "endpoints": endpoints,
            "auth_schemes": auth,
            "global_security": global_security,
            "schemas": schemas,
        }

    def _extract_endpoints(self, paths: dict) -> list[dict[str, Any]]:
        endpoints = []
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.startswith("x-") or not isinstance(details, dict):
                    continue
                endpoints.append(
                    {
                        "path": path,
                        "method": method.upper(),
                        "operation_id": details.get("operationId"),
                        "summary": details.get("summary"),
                        "tags": details.get("tags", []),
                        "security": details.get("security", []),
                        "parameters": self._extract_parameters(details.get("parameters", [])),
                        "request_body": self._extract_request_body(details.get("requestBody")),
                        "responses": self._extract_responses(details.get("responses", {})),
                    }
                )
        return endpoints

    @staticmethod
    def _extract_parameters(params: list) -> list[dict[str, Any]]:
        return [
            {
                "name": p.get("name"),
                "in": p.get("in"),
                "required": p.get("required", False),
                "schema_type": (p.get("schema") or {}).get("type"),
            }
            for p in params
        ]

    @staticmethod
    def _extract_request_body(body: dict | None) -> dict[str, Any] | None:
        if not body:
            return None
        content = body.get("content", {})
        result: dict[str, Any] = {"required": body.get("required", False)}

        for content_type, media in content.items():
            schema = media.get("schema", {})
            result["content_type"] = content_type
            result["schema_ref"] = schema.get("$ref")
            if not result["schema_ref"]:
                result["schema_inline"] = {
                    "type": schema.get("type"),
                    "properties": list((schema.get("properties") or {}).keys()),
                }
            break  # take first content type
        return result

    @staticmethod
    def _extract_responses(responses: dict) -> list[dict[str, Any]]:
        result = []
        for status, resp in responses.items():
            entry: dict[str, Any] = {
                "status": str(status),
                "description": resp.get("description", ""),
            }
            content = resp.get("content", {})
            if content:
                for content_type, media in content.items():
                    schema = media.get("schema", {})
                    entry["content_type"] = content_type
                    entry["schema_ref"] = schema.get("$ref")
                    if not entry.get("schema_ref"):
                        entry["schema_inline"] = {
                            "type": schema.get("type"),
                            "properties": list((schema.get("properties") or {}).keys()),
                        }
                    break
            result.append(entry)
        return result

    def _extract_security(self, raw: dict) -> list[dict[str, Any]]:
        schemes = raw.get("components", {}).get("securitySchemes", {}) or raw.get(
            "securityDefinitions", {}
        )
        return [
            {
                "name": name,
                "type": cfg.get("type"),
                "scheme": cfg.get("scheme"),
                "in": cfg.get("in"),
                "bearer_format": cfg.get("bearerFormat"),
            }
            for name, cfg in schemes.items()
        ]

    @staticmethod
    def _extract_schemas(raw: dict) -> list[dict[str, Any]]:
        raw_schemas = raw.get("components", {}).get("schemas", {})
        if not raw_schemas:
            raw_schemas = raw.get("definitions", {})

        schemas = []
        for name, defn in raw_schemas.items():
            props = defn.get("properties", {})
            prop_details = []
            for prop_name, prop_cfg in props.items():
                prop_details.append(
                    {
                        "name": prop_name,
                        "type": prop_cfg.get("type"),
                        "format": prop_cfg.get("format"),
                        "enum": prop_cfg.get("enum"),
                        "ref": prop_cfg.get("$ref"),
                    }
                )
            schemas.append(
                {
                    "name": name,
                    "type": defn.get("type"),
                    "properties": prop_details,
                    "required": defn.get("required", []),
                }
            )
        return schemas
