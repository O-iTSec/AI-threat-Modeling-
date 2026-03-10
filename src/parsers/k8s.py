"""Parser for Kubernetes manifests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class K8sParser:
    """Extract workloads, services, and network policies from K8s YAML manifests."""

    SUPPORTED_KINDS = (
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "Service",
        "Ingress",
        "NetworkPolicy",
        "ConfigMap",
        "Secret",
    )

    def parse(self, path: Path) -> dict[str, Any]:
        """Parse one or more K8s resources from a YAML file (supports multi-doc)."""
        with open(path) as fh:
            docs = list(yaml.safe_load_all(fh))

        resources: list[dict[str, Any]] = []
        for doc in docs:
            if doc is None:
                continue
            kind = doc.get("kind", "Unknown")
            resources.append(self._normalise(kind, doc))

        return {"source": "k8s", "resources": resources}

    def _normalise(self, kind: str, doc: dict) -> dict[str, Any]:
        metadata = doc.get("metadata", {})
        spec = doc.get("spec", {})
        return {
            "kind": kind,
            "name": metadata.get("name", "unnamed"),
            "namespace": metadata.get("namespace", "default"),
            "labels": metadata.get("labels", {}),
            "spec_summary": self._summarise_spec(kind, spec),
        }

    def _summarise_spec(self, kind: str, spec: dict) -> dict[str, Any]:
        if kind in ("Deployment", "StatefulSet", "DaemonSet"):
            containers = []
            template_spec = spec.get("template", {}).get("spec", {})
            for c in template_spec.get("containers", []):
                containers.append(
                    {
                        "name": c.get("name"),
                        "image": c.get("image"),
                        "ports": [p.get("containerPort") for p in c.get("ports", [])],
                    }
                )
            return {"replicas": spec.get("replicas", 1), "containers": containers}
        if kind == "Service":
            return {
                "type": spec.get("type", "ClusterIP"),
                "ports": spec.get("ports", []),
                "selector": spec.get("selector", {}),
            }
        if kind == "Ingress":
            return {"rules": spec.get("rules", []), "tls": spec.get("tls", [])}
        return spec
