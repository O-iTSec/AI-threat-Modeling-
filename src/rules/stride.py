"""STRIDE threat classification templates and matching logic."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.graph.assets import AssetGraph
from src.graph.flows import DataFlow
from src.rules.trust_boundaries import TrustBoundary

STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)


@dataclass
class Threat:
    """A single identified threat against an asset or flow."""

    id: str
    category: str
    title: str
    description: str
    affected_asset_ids: list[str] = field(default_factory=list)
    boundary_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


_TEMPLATES: dict[str, list[dict[str, str]]] = {
    "service": [
        {
            "category": "Spoofing",
            "title": "Service identity spoofing",
            "desc": "An attacker may impersonate {name} if mutual auth is absent.",
        },
        {
            "category": "Tampering",
            "title": "Unauthorised config mutation",
            "desc": "Environment variables or mounted volumes on {name} could be tampered with.",
        },
        {
            "category": "Denial of Service",
            "title": "Resource exhaustion",
            "desc": "{name} may be overwhelmed without rate-limiting or resource quotas.",
        },
        {
            "category": "Repudiation",
            "title": "Insufficient logging",
            "desc": "{name} may lack audit logging for security-relevant actions.",
        },
    ],
    "datastore": [
        {
            "category": "Information Disclosure",
            "title": "Unencrypted data at rest",
            "desc": "Datastore {name} may store sensitive data without encryption.",
        },
        {
            "category": "Tampering",
            "title": "Unauthorised data modification",
            "desc": (
                "Datastore {name} may accept writes from untrusted services without authz checks."
            ),
        },
        {
            "category": "Spoofing",
            "title": "Default or weak credentials",
            "desc": "Datastore {name} may use default or weak authentication credentials.",
        },
        {
            "category": "Denial of Service",
            "title": "Connection pool exhaustion",
            "desc": "Datastore {name} may be overwhelmed by unbounded client connections.",
        },
    ],
    "external": [
        {
            "category": "Spoofing",
            "title": "External actor impersonation",
            "desc": (
                "External actor {name} identity cannot be verified without strong authentication."
            ),
        },
        {
            "category": "Repudiation",
            "title": "Unattributable external actions",
            "desc": (
                "Actions by {name} may not be traceable without request "
                "logging and correlation IDs."
            ),
        },
        {
            "category": "Tampering",
            "title": "Man-in-the-middle on external channel",
            "desc": "Traffic from {name} may be intercepted if TLS is not enforced.",
        },
    ],
    "secret": [
        {
            "category": "Information Disclosure",
            "title": "Secret exposure in environment",
            "desc": "Secret {name} may be leaked via process listing, logs, or crash dumps.",
        },
        {
            "category": "Spoofing",
            "title": "Credential theft enables impersonation",
            "desc": "Compromise of {name} allows an attacker to impersonate the owning service.",
        },
        {
            "category": "Elevation of Privilege",
            "title": "Overprivileged secret scope",
            "desc": (
                "Secret {name} may grant broader access than required (violating least privilege)."
            ),
        },
    ],
    "storage": [
        {
            "category": "Information Disclosure",
            "title": "Unencrypted persistent volume",
            "desc": "Storage {name} may persist data without encryption at rest.",
        },
        {
            "category": "Tampering",
            "title": "Writable by untrusted workloads",
            "desc": "Storage {name} may be mounted read-write by containers that should only read.",
        },
        {
            "category": "Denial of Service",
            "title": "Storage capacity exhaustion",
            "desc": "Storage {name} has no quota — a runaway process could fill the volume.",
        },
    ],
}


class StrideAnalyzer:
    """Apply STRIDE templates to assets and flows, producing a threat list."""

    def analyze(
        self,
        graph: AssetGraph,
        flows: list[DataFlow],
        boundaries: list[TrustBoundary],
    ) -> list[Threat]:
        threats: list[Threat] = []
        boundary_lookup = self._build_boundary_lookup(boundaries)

        for asset in sorted(graph.all_assets(), key=lambda a: a.id):
            templates = _TEMPLATES.get(asset.kind, [])
            for tmpl in templates:
                threats.append(
                    Threat(
                        id=f"threat:{asset.id}:{tmpl['category']}",
                        category=tmpl["category"],
                        title=tmpl["title"],
                        description=tmpl["desc"].format(name=asset.name),
                        affected_asset_ids=[asset.id],
                        boundary_id=boundary_lookup.get(asset.id),
                        metadata={"evidence": {"asset_id": asset.id, "asset_kind": asset.kind}},
                    )
                )

        threats.extend(self._public_endpoint_threats(graph, flows, boundary_lookup))
        threats.extend(self._edge_threats(flows, boundary_lookup))
        threats.extend(self._cross_boundary_threats(flows, boundary_lookup))
        threats.sort(key=lambda t: t.id)
        return threats

    def _build_boundary_lookup(self, boundaries: list[TrustBoundary]) -> dict[str, str]:
        lookup: dict[str, list[str]] = {}
        for b in sorted(boundaries, key=lambda x: x.id):
            for aid in b.asset_ids:
                lookup.setdefault(aid, []).append(b.id)
        # Keep primary boundary deterministic by choosing lexicographically smallest id
        return {aid: sorted(ids)[0] for aid, ids in lookup.items()}

    def _public_endpoint_threats(
        self,
        graph: AssetGraph,
        flows: list[DataFlow],
        lookup: dict[str, str],
    ) -> list[Threat]:
        """Public endpoint STRIDE templates for services reachable from external actors."""
        public_targets = {f.target.id for f in flows if f.edge_type in ("exposes", "calls_api")}
        threats: list[Threat] = []
        for asset in sorted(graph.all_assets(), key=lambda a: a.id):
            if asset.id not in public_targets or asset.kind != "service":
                continue
            title = "Public endpoint without strict auth/rate controls"
            threats.append(
                Threat(
                    id=f"threat:public-endpoint:{asset.id}:Spoofing",
                    category="Spoofing",
                    title=title,
                    description=(
                        f"Public endpoint on {asset.name} is reachable from an external boundary. "
                        "Strong authentication and anti-automation controls are required."
                    ),
                    affected_asset_ids=[asset.id],
                    boundary_id=lookup.get(asset.id),
                    metadata={"evidence": {"public_flow_targets": sorted(public_targets)}},
                )
            )
            threats.append(
                Threat(
                    id=f"threat:public-endpoint:{asset.id}:Information Disclosure",
                    category="Information Disclosure",
                    title="Public endpoint may leak sensitive data",
                    description=(
                        f"Public endpoint on {asset.name} may expose sensitive response data "
                        "without strict output controls and least-privilege access."
                    ),
                    affected_asset_ids=[asset.id],
                    boundary_id=lookup.get(asset.id),
                    metadata={"evidence": {"public_flow_targets": sorted(public_targets)}},
                )
            )
        return threats

    def _edge_threats(
        self,
        flows: list[DataFlow],
        lookup: dict[str, str],
    ) -> list[Threat]:
        """STRIDE templates for data-flow edges."""
        threats: list[Threat] = []
        for flow in sorted(flows, key=lambda f: f.id):
            if flow.edge_type == "connects_to":
                threats.append(
                    Threat(
                        id=f"threat:edge:{flow.id}:Tampering",
                        category="Tampering",
                        title="Data flow integrity risk",
                        description=(
                            f"Data flow {flow.source.name} -> {flow.target.name} "
                            "may be tampered with if integrity controls are absent."
                        ),
                        affected_asset_ids=[flow.source.id, flow.target.id],
                        boundary_id=lookup.get(flow.target.id),
                        metadata={"evidence": flow.to_dict()},
                    )
                )
            elif flow.edge_type == "exposes":
                threats.append(
                    Threat(
                        id=f"threat:edge:{flow.id}:Denial of Service",
                        category="Denial of Service",
                        title="Publicly exposed flow can be flooded",
                        description=(
                            f"Exposed flow to {flow.target.name} on port {flow.port} can be abused "
                            "for resource exhaustion without upstream limits."
                        ),
                        affected_asset_ids=[flow.source.id, flow.target.id],
                        boundary_id=lookup.get(flow.target.id),
                        metadata={"evidence": flow.to_dict()},
                    )
                )
            elif flow.edge_type == "calls_api":
                threats.append(
                    Threat(
                        id=f"threat:edge:{flow.id}:Repudiation",
                        category="Repudiation",
                        title="API call traceability gap",
                        description=(
                            f"API calls from {flow.source.name} to {flow.target.name} "
                            "may be untraceable without request IDs and immutable audit logs."
                        ),
                        affected_asset_ids=[flow.source.id, flow.target.id],
                        boundary_id=lookup.get(flow.target.id),
                        metadata={"evidence": flow.to_dict()},
                    )
                )
        return threats

    def _cross_boundary_threats(
        self,
        flows: list[DataFlow],
        lookup: dict[str, str],
    ) -> list[Threat]:
        threats = []
        for flow in sorted(flows, key=lambda f: f.id):
            src_b = lookup.get(flow.source.id)
            tgt_b = lookup.get(flow.target.id)
            if src_b and tgt_b and src_b != tgt_b:
                threats.append(
                    Threat(
                        id=f"threat:cross-boundary:{flow.id}",
                        category="Tampering",
                        title="Cross-boundary data flow",
                        description=(
                            f"Data flows from {flow.source.name} to {flow.target.name} "
                            f"across trust boundaries ({src_b} → {tgt_b})."
                        ),
                        affected_asset_ids=[flow.source.id, flow.target.id],
                        metadata={"evidence": {"source_boundary": src_b, "target_boundary": tgt_b}},
                    )
                )
        return threats
