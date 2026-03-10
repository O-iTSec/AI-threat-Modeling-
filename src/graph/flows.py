"""Build typed data-flow edges between assets in the graph.

Canonical edge types:
  connects_to — internal service-to-service or service-to-datastore dependency
  exposes     — asset is reachable from outside a trust boundary
  calls_api   — external actor invokes an API endpoint
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.graph.assets import Asset, AssetGraph

EDGE_TYPES = ("connects_to", "exposes", "calls_api")


@dataclass
class DataFlow:
    """Directed edge representing data movement between two assets."""

    id: str
    source: Asset
    target: Asset
    edge_type: str
    protocol: str = "unknown"
    port: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "source": self.source.id,
            "target": self.target.id,
            "edge_type": self.edge_type,
            "protocol": self.protocol,
        }
        if self.port is not None:
            d["port"] = self.port
        if self.metadata:
            d["metadata"] = self.metadata
        return d


class FlowBuilder:
    """Infer typed data-flow edges from asset properties."""

    def build(self, graph: AssetGraph) -> list[DataFlow]:
        flows: list[DataFlow] = []
        flows.extend(self._compose_dependency_flows(graph))
        flows.extend(self._compose_expose_flows(graph))
        flows.extend(self._compose_secret_flows(graph))
        flows.extend(self._compose_storage_flows(graph))
        flows.extend(self._k8s_selector_flows(graph))
        flows.extend(self._k8s_expose_flows(graph))
        flows.extend(self._openapi_flows(graph))
        return flows

    # -- Compose edges --------------------------------------------------------

    def _compose_dependency_flows(self, graph: AssetGraph) -> list[DataFlow]:
        """depends_on → connects_to edges between services/datastores."""
        flows = []
        for asset in graph.all_assets():
            if not asset.id.startswith("compose:"):
                continue
            if asset.kind not in ("service", "datastore"):
                continue
            for dep in asset.properties.get("depends_on", []):
                target = graph.get(f"compose:service:{dep}") or graph.get(
                    f"compose:datastore:{dep}"
                )
                if target:
                    flows.append(
                        DataFlow(
                            id=f"flow:{asset.id}->{target.id}",
                            source=asset,
                            target=target,
                            edge_type="connects_to",
                            metadata={"reason": "depends_on"},
                        )
                    )
        return flows

    def _compose_expose_flows(self, graph: AssetGraph) -> list[DataFlow]:
        """Exposed ports → exposes edges from external:internet."""
        external = graph.get("external:internet")
        if not external:
            return []

        flows = []
        for asset in graph.all_assets():
            if not asset.id.startswith("compose:"):
                continue
            ports = asset.properties.get("ports", [])
            if not ports:
                continue
            for p in ports:
                host_port = p.get("host") if isinstance(p, dict) else None
                container_port = p.get("container") if isinstance(p, dict) else None
                protocol = p.get("protocol", "tcp") if isinstance(p, dict) else "tcp"
                flows.append(
                    DataFlow(
                        id=f"flow:external:internet->{asset.id}:{container_port}",
                        source=external,
                        target=asset,
                        edge_type="exposes",
                        protocol=protocol,
                        port=host_port or container_port,
                        metadata={"host_port": host_port, "container_port": container_port},
                    )
                )
        return flows

    def _compose_secret_flows(self, graph: AssetGraph) -> list[DataFlow]:
        """Service reads sensitive env var → connects_to secret node."""
        flows = []
        for secret in graph.assets_by_kind("secret"):
            if not secret.id.startswith("compose:secret:"):
                continue
            owner = secret.properties.get("owner_service")
            if not owner:
                continue
            owner_asset = graph.get(f"compose:service:{owner}") or graph.get(
                f"compose:datastore:{owner}"
            )
            if owner_asset:
                flows.append(
                    DataFlow(
                        id=f"flow:{owner_asset.id}->{secret.id}",
                        source=owner_asset,
                        target=secret,
                        edge_type="connects_to",
                        metadata={"reason": "env_var"},
                    )
                )
        return flows

    def _compose_storage_flows(self, graph: AssetGraph) -> list[DataFlow]:
        """Volume mounts → connects_to edges from storage to service/datastore."""
        flows = []
        for asset in graph.all_assets():
            if not asset.id.startswith("compose:"):
                continue
            if asset.kind not in ("service", "datastore"):
                continue
            for vol in asset.properties.get("volumes", []):
                vol_name = vol.get("volume") if isinstance(vol, dict) else None
                if not vol_name:
                    continue
                storage = graph.get(f"compose:storage:{vol_name}")
                if storage:
                    flows.append(
                        DataFlow(
                            id=f"flow:{storage.id}->{asset.id}",
                            source=storage,
                            target=asset,
                            edge_type="connects_to",
                            metadata={
                                "reason": "volume_mount",
                                "mount_path": vol.get("mount_path"),
                                "mode": vol.get("mode", "rw"),
                            },
                        )
                    )
        return flows

    # -- K8s edges ------------------------------------------------------------

    def _k8s_selector_flows(self, graph: AssetGraph) -> list[DataFlow]:
        """K8s Service selector → connects_to matching workloads."""
        flows = []
        for asset in graph.all_assets():
            if not asset.id.startswith("k8s:"):
                continue
            selector = asset.properties.get("spec_summary", {}).get("selector", {})
            if not selector:
                continue
            for candidate in graph.all_assets():
                if candidate.id == asset.id or not candidate.id.startswith("k8s:"):
                    continue
                labels = candidate.properties.get("labels", {})
                if all(labels.get(k) == v for k, v in selector.items()):
                    flows.append(
                        DataFlow(
                            id=f"flow:{asset.id}->{candidate.id}",
                            source=asset,
                            target=candidate,
                            edge_type="connects_to",
                            metadata={"reason": "selector_match"},
                        )
                    )
        return flows

    def _k8s_expose_flows(self, graph: AssetGraph) -> list[DataFlow]:
        """Ingress resources → exposes edges from external:internet."""
        external = graph.get("external:internet")
        if not external:
            return []
        flows = []
        for asset in graph.all_assets():
            if "exposed" in asset.tags and asset.id.startswith("k8s:"):
                flows.append(
                    DataFlow(
                        id=f"flow:external:internet->{asset.id}",
                        source=external,
                        target=asset,
                        edge_type="exposes",
                        metadata={"reason": "ingress"},
                    )
                )
        return flows

    # -- OpenAPI edges --------------------------------------------------------

    def _openapi_flows(self, graph: AssetGraph) -> list[DataFlow]:
        """External API caller → calls_api → API service."""
        caller = graph.get("external:api-caller")
        if not caller:
            return []

        flows = []
        for asset in graph.all_assets():
            if not asset.id.startswith("openapi:service:"):
                continue
            endpoints = asset.properties.get("endpoints", [])
            endpoint_summaries = [
                f"{ep.get('method', '?')} {ep.get('path', '?')}" for ep in endpoints
            ]
            flows.append(
                DataFlow(
                    id=f"flow:external:api-caller->{asset.id}",
                    source=caller,
                    target=asset,
                    edge_type="calls_api",
                    metadata={"endpoints": endpoint_summaries},
                )
            )
        return flows
