"""Serialize the asset graph to JSON and human-readable Markdown."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.graph.assets import AssetGraph
from src.graph.flows import DataFlow


class GraphExporter:
    """Write graph.json and graph.md to an output directory."""

    def __init__(self, source_file: Path | str | None = None) -> None:
        self.source_file = str(source_file) if source_file else "unknown"

    def export_json(
        self,
        graph: AssetGraph,
        flows: list[DataFlow],
        output_path: Path,
    ) -> Path:
        nodes = [a.to_dict() for a in graph.all_assets()]
        edges = [f.to_dict() for f in flows]
        payload: dict[str, Any] = {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "generated_at": datetime.now(UTC).isoformat(),
                "source_file": self.source_file,
                "node_count": len(nodes),
                "edge_count": len(edges),
            },
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as fh:
            json.dump(payload, fh, indent=2, default=str)
        return output_path

    def export_markdown(
        self,
        graph: AssetGraph,
        flows: list[DataFlow],
        output_path: Path,
    ) -> Path:
        assets = graph.all_assets()
        lines: list[str] = []

        lines.append("# Threat Model Graph\n")
        lines.append(f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}  ")
        lines.append(f"Source: `{self.source_file}`\n")

        # -- Nodes table ------------------------------------------------------
        lines.append(f"## Nodes ({len(assets)})\n")
        lines.append("| ID | Kind | Name | Tags |")
        lines.append("|----|------|------|------|")
        for a in assets:
            tags = ", ".join(a.tags) if a.tags else ""
            lines.append(f"| {a.id} | {a.kind} | {a.name} | {tags} |")
        lines.append("")

        # -- Edges table ------------------------------------------------------
        lines.append(f"## Edges ({len(flows)})\n")
        lines.append("| Source | \u2192 | Target | Type | Detail |")
        lines.append("|--------|---|--------|------|--------|")
        for f in flows:
            detail = f.metadata.get("reason", "")
            if f.port is not None:
                detail = f"port {f.port}"
            if f.edge_type == "calls_api":
                eps = f.metadata.get("endpoints", [])
                detail = f"{len(eps)} endpoints"
            lines.append(
                f"| {f.source.name} | \u2192 | {f.target.name} | {f.edge_type} | {detail} |"
            )
        lines.append("")

        # -- Summary ----------------------------------------------------------
        kind_counts = Counter(a.kind for a in assets)
        edge_counts = Counter(f.edge_type for f in flows)

        lines.append("## Summary\n")
        kind_parts = [f"**{c}** {k}" for k, c in kind_counts.most_common()]
        lines.append(f"- {', '.join(kind_parts)}")
        edge_parts = [f"**{c}** {t}" for t, c in edge_counts.most_common()]
        lines.append(f"- {', '.join(edge_parts)}")
        lines.append("")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines))
        return output_path
