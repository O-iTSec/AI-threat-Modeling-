"""Normalise parsed inputs into a unified asset graph.

Canonical node types:
  service   — application component (web server, API, worker)
  datastore — database, cache, message queue
  external  — actor outside the system boundary (internet, API caller)
  secret    — credential, token, or sensitive env var
  storage   — persistent volume or object store
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

NODE_TYPES = ("service", "datastore", "external", "secret", "storage")


@dataclass
class Asset:
    """Single node in the threat-model graph."""

    id: str
    kind: str
    name: str
    properties: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "tags": self.tags,
            "properties": self.properties,
        }


class AssetGraph:
    """In-memory graph of all assets discovered from parsed input."""

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}

    def add_assets(self, parsed: dict[str, Any]) -> None:
        source = parsed.get("source", "unknown")
        handler = {
            "compose": self._ingest_compose,
            "k8s": self._ingest_k8s,
            "openapi": self._ingest_openapi,
        }.get(source)
        if handler is None:
            raise ValueError(f"Unknown source type: {source}")
        handler(parsed)

    def get(self, asset_id: str) -> Asset | None:
        return self._assets.get(asset_id)

    def all_assets(self) -> list[Asset]:
        return list(self._assets.values())

    def assets_by_kind(self, kind: str) -> list[Asset]:
        return [a for a in self._assets.values() if a.kind == kind]

    def _register(self, asset: Asset) -> None:
        self._assets[asset.id] = asset

    # -- Compose ingestion ----------------------------------------------------

    def _ingest_compose(self, parsed: dict) -> None:
        for svc in parsed.get("services", []):
            asset_type = svc.get("asset_type", "service")
            kind = asset_type if asset_type in NODE_TYPES else "service"
            svc_id = f"compose:{kind}:{svc['name']}"

            tags = []
            if svc.get("ports"):
                tags.append("exposed")

            self._register(
                Asset(
                    id=svc_id,
                    kind=kind,
                    name=svc["name"],
                    properties=svc,
                    tags=tags,
                )
            )

            # Create secret nodes for sensitive env vars
            for env in svc.get("environment", []):
                if isinstance(env, dict) and env.get("sensitive"):
                    secret_id = f"compose:secret:{svc['name']}:{env['key']}"
                    self._register(
                        Asset(
                            id=secret_id,
                            kind="secret",
                            name=env["key"],
                            properties={"key": env["key"], "owner_service": svc["name"]},
                            tags=["sensitive"],
                        )
                    )

        # Storage nodes from top-level volumes
        for vol in parsed.get("volumes", []):
            self._register(
                Asset(
                    id=f"compose:storage:{vol['name']}",
                    kind="storage",
                    name=vol["name"],
                    properties=vol,
                )
            )

        # External node for internet-facing services
        exposed = [s for s in parsed.get("services", []) if s.get("ports")]
        if exposed:
            self._register(
                Asset(
                    id="external:internet",
                    kind="external",
                    name="internet",
                    properties={"description": "External network / internet"},
                )
            )

    # -- K8s ingestion --------------------------------------------------------

    _K8S_KIND_MAP = {
        "deployment": "service",
        "statefulset": "service",
        "daemonset": "service",
        "service": "service",
        "ingress": "service",
        "configmap": "secret",
        "secret": "secret",
        "persistentvolumeclaim": "storage",
    }

    def _ingest_k8s(self, parsed: dict) -> None:
        for res in parsed.get("resources", []):
            raw_kind = res["kind"].lower()
            kind = self._K8S_KIND_MAP.get(raw_kind, "service")
            tags = []
            if raw_kind == "ingress":
                tags.append("exposed")
            self._register(
                Asset(
                    id=f"k8s:{kind}:{res['name']}",
                    kind=kind,
                    name=res["name"],
                    properties=res,
                    tags=tags,
                )
            )

        # External node if any ingress exists
        has_ingress = any(r["kind"].lower() == "ingress" for r in parsed.get("resources", []))
        if has_ingress:
            self._register(
                Asset(
                    id="external:internet",
                    kind="external",
                    name="internet",
                    properties={"description": "External network / internet"},
                )
            )

    # -- OpenAPI ingestion ----------------------------------------------------

    def _ingest_openapi(self, parsed: dict) -> None:
        title = parsed.get("title", "API")
        api_id = f"openapi:service:{title.lower().replace(' ', '-')}"
        self._register(
            Asset(
                id=api_id,
                kind="service",
                name=title,
                properties={
                    "endpoints": parsed.get("endpoints", []),
                    "auth_schemes": parsed.get("auth_schemes", []),
                    "schemas": parsed.get("schemas", []),
                    "servers": parsed.get("servers", []),
                },
            )
        )

        self._register(
            Asset(
                id="external:api-caller",
                kind="external",
                name="API Caller",
                properties={"description": "External client consuming the API"},
            )
        )
