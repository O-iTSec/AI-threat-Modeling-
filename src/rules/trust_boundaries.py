"""Detect and classify trust boundaries in the asset graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.graph.assets import AssetGraph
from src.graph.flows import DataFlow


@dataclass
class TrustBoundary:
    """A logical perimeter separating zones of different trust levels."""

    id: str
    name: str
    level: int  # higher = more trusted
    asset_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class TrustBoundaryDetector:
    """Heuristic detection of trust boundaries from asset topology.

    Boundaries are inferred from:
    - Network segmentation (Compose network membership on services)
    - K8s namespace isolation
    - Exposure (ports, ingress → external boundary)
    - Datastore isolation (datastores form their own trust zone)
    """

    EXTERNAL_TRUST = 0
    DMZ_TRUST = 1
    INTERNAL_TRUST = 2
    DATASTORE_TRUST = 3

    def detect(
        self,
        graph: AssetGraph,
        flows: list[DataFlow],
    ) -> list[TrustBoundary]:
        boundaries: list[TrustBoundary] = []
        boundaries.extend(self._from_networks(graph))
        boundaries.extend(self._from_namespaces(graph))
        boundaries.extend(self._from_datastores(graph))
        boundaries.extend(self._from_public_ingress(graph, flows))
        boundaries.extend(self._from_service_to_service(graph, flows))
        boundaries.extend(self._from_secrets(graph, flows))
        boundaries.sort(key=lambda b: b.id)
        return boundaries

    def _from_networks(self, graph: AssetGraph) -> list[TrustBoundary]:
        """Infer network boundaries from Compose service network membership."""
        net_map: dict[str, list[str]] = {}
        for asset in graph.all_assets():
            if not asset.id.startswith("compose:"):
                continue
            if asset.kind not in ("service", "datastore"):
                continue
            for net_name in asset.properties.get("networks", []):
                net_map.setdefault(net_name, []).append(asset.id)

        boundaries = [
            TrustBoundary(
                id=f"boundary:network:{net}",
                name=f"Network: {net}",
                level=self.INTERNAL_TRUST,
                asset_ids=sorted(ids),
                metadata={"network": net},
            )
            for net, ids in net_map.items()
        ]
        boundaries.sort(key=lambda b: b.id)
        return boundaries

    def _from_namespaces(self, graph: AssetGraph) -> list[TrustBoundary]:
        ns_map: dict[str, list[str]] = {}
        for asset in graph.all_assets():
            if not asset.id.startswith("k8s:"):
                continue
            ns = asset.properties.get("namespace", "default")
            ns_map.setdefault(ns, []).append(asset.id)

        boundaries = [
            TrustBoundary(
                id=f"boundary:namespace:{ns}",
                name=f"K8s namespace: {ns}",
                level=self.INTERNAL_TRUST,
                asset_ids=sorted(ids),
                metadata={"namespace": ns},
            )
            for ns, ids in ns_map.items()
        ]
        boundaries.sort(key=lambda b: b.id)
        return boundaries

    def _from_public_ingress(self, graph: AssetGraph, flows: list[DataFlow]) -> list[TrustBoundary]:
        """Public ingress boundary: published ports, ingress, public API calls."""
        ingress_targets = {f.target.id for f in flows if f.edge_type in ("exposes", "calls_api")}
        external_ids = {a.id for a in graph.assets_by_kind("external")}
        all_ids = sorted(ingress_targets | external_ids)
        if not all_ids:
            return []

        evidence = sorted(f.id for f in flows if f.edge_type in ("exposes", "calls_api"))
        return [
            TrustBoundary(
                id="boundary:public-ingress",
                name="Public ingress",
                level=self.EXTERNAL_TRUST,
                asset_ids=all_ids,
                metadata={"evidence_flows": evidence},
            )
        ]

    def _from_datastores(self, graph: AssetGraph) -> list[TrustBoundary]:
        ds_ids = [a.id for a in graph.assets_by_kind("datastore")]
        if not ds_ids:
            return []
        return [
            TrustBoundary(
                id="boundary:datastore",
                name="Datastore tier",
                level=self.DATASTORE_TRUST,
                asset_ids=sorted(ds_ids),
            )
        ]

    def _from_service_to_service(
        self,
        graph: AssetGraph,
        flows: list[DataFlow],
    ) -> list[TrustBoundary]:
        """Boundary crossings between services in different networks/namespaces."""
        boundaries: list[TrustBoundary] = []
        for flow in sorted(flows, key=lambda f: f.id):
            if flow.edge_type != "connects_to":
                continue
            src = flow.source
            tgt = flow.target
            if src.kind not in ("service", "datastore") or tgt.kind not in ("service", "datastore"):
                continue
            src_nets = set(src.properties.get("networks", []))
            tgt_nets = set(tgt.properties.get("networks", []))
            src_ns = src.properties.get("namespace")
            tgt_ns = tgt.properties.get("namespace")

            crosses_network = bool(src_nets and tgt_nets and src_nets.isdisjoint(tgt_nets))
            crosses_namespace = bool(src_ns and tgt_ns and src_ns != tgt_ns)
            if not (crosses_network or crosses_namespace):
                continue

            boundaries.append(
                TrustBoundary(
                    id=f"boundary:service-to-service:{flow.id}",
                    name="Service-to-service boundary",
                    level=self.DMZ_TRUST,
                    asset_ids=sorted([src.id, tgt.id]),
                    metadata={
                        "flow_id": flow.id,
                        "crosses_network": crosses_network,
                        "crosses_namespace": crosses_namespace,
                        "source_networks": sorted(src_nets),
                        "target_networks": sorted(tgt_nets),
                        "source_namespace": src_ns,
                        "target_namespace": tgt_ns,
                    },
                )
            )
        return boundaries

    def _from_secrets(self, graph: AssetGraph, flows: list[DataFlow]) -> list[TrustBoundary]:
        """Secrets boundary: env secrets and mounted secrets."""
        secret_ids = [a.id for a in graph.assets_by_kind("secret")]
        if not secret_ids:
            return []

        evidence_flows = sorted(
            f.id
            for f in flows
            if f.target.kind == "secret" or f.metadata.get("reason") in ("env_var", "secret_mount")
        )
        return [
            TrustBoundary(
                id="boundary:secrets",
                name="Secrets boundary",
                level=self.DMZ_TRUST,
                asset_ids=sorted(secret_ids),
                metadata={"evidence_flows": evidence_flows},
            )
        ]
