"""Command-line interface for the AI threat modelling engine."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from src.graph.assets import AssetGraph
from src.graph.export import GraphExporter
from src.graph.flows import FlowBuilder
from src.llm.guardrails import OutputGuardrail
from src.llm.prompts import PromptEngine
from src.mitre.mapping import MitreMapper
from src.parsers.compose import ComposeParser
from src.parsers.k8s import K8sParser
from src.parsers.openapi import OpenAPIParser
from src.reporting.pdf import PDFReporter
from src.reporting.sarif import SARIFReporter
from src.rules.stride import StrideAnalyzer
from src.rules.trust_boundaries import TrustBoundaryDetector
from src.scoring.engine import RiskScorer

PARSERS = {
    "compose": ComposeParser,
    "k8s": K8sParser,
    "openapi": OpenAPIParser,
}


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-threat-model",
        description="Generate threat models from infrastructure and API definitions.",
    )
    parser.add_argument("input", type=Path, help="Path to input file or directory")
    parser.add_argument(
        "-t",
        "--type",
        choices=PARSERS.keys(),
        required=True,
        help="Input format type",
    )
    parser.add_argument(
        "-p",
        "--policy",
        type=Path,
        default=Path("policies/default.yml"),
        help="Policy file for scoring thresholds",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("report"),
        help="Output path for reports (without extension)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("outputs"),
        help="Directory for graph.json and graph.md",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["pdf", "sarif", "both"],
        default="both",
        help="Report output format",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM-enhanced analysis",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.input.exists():
        print(f"Error: input path '{args.input}' not found.", file=sys.stderr)
        return 1

    # 1. Parse
    parsed = PARSERS[args.type]().parse(args.input)

    # 2. Build graph
    graph = AssetGraph()
    graph.add_assets(parsed)
    flows = FlowBuilder().build(graph)

    # 3. Export graph (before analysis so it's available even if downstream fails)
    exporter = GraphExporter(source_file=args.input)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    exporter.export_json(graph, flows, args.output_dir / "graph.json")
    exporter.export_markdown(graph, flows, args.output_dir / "graph.md")

    # 4. Detect trust boundaries & apply STRIDE
    boundaries = TrustBoundaryDetector().detect(graph, flows)
    threats = StrideAnalyzer().analyze(graph, flows, boundaries)

    # 5. Map to MITRE ATT&CK
    mapped = MitreMapper().map(threats)

    # 6. LLM-enhanced analysis (optional)
    llm_insights: dict | None = None
    if not args.no_llm:
        engine = PromptEngine(policy_path=args.policy)
        guardrail = OutputGuardrail()
        llm_result = engine.enrich(mapped)
        if llm_result.get("llm_error"):
            print(f"Warning: LLM enrichment failed — {llm_result['llm_error']}", file=sys.stderr)
        llm_insights = guardrail.validate(llm_result)

    # 7. Score
    scorer = RiskScorer(policy_path=args.policy)
    scored = scorer.score(mapped)
    if llm_insights:
        scored = _apply_llm_augmentations(scored, llm_insights)

    findings_path = args.output_dir / "findings.json"
    findings_payload = _build_findings_payload(scored)
    _validate_high_critical_mitre_coverage(findings_payload)
    with open(findings_path, "w") as fh:
        json.dump(findings_payload, fh, indent=2, default=str)

    if llm_insights:
        _write_llm_artifacts(args.output_dir, llm_insights)

    # 8. Report
    if args.format in ("pdf", "both"):
        PDFReporter().generate(scored, args.output.with_suffix(".pdf"))
    if args.format in ("sarif", "both"):
        SARIFReporter().generate(scored, args.output.with_suffix(".sarif"))

    gate = scorer.evaluate_build_gate(scored)
    if not gate["passed"]:
        print(
            "Policy gate failed (risk score threshold "
            f"{gate['threshold']}): "
            + ", ".join(f"{item['id']} [{item['risk_score']}]" for item in gate["violations"]),
            file=sys.stderr,
        )
        return 2

    print(f"Threat model generated → {args.output}")
    print(
        "Graph exported → "
        f"{args.output_dir}/graph.json, {args.output_dir}/graph.md, "
        f"{args.output_dir}/findings.json"
    )
    return 0


def _build_findings_payload(scored: dict) -> list[dict]:
    """Normalize scored threats into deterministic finding records."""
    findings: list[dict] = []
    for entry in scored.get("threats", []):
        threat = entry.get("threat", entry)
        asset = ",".join(sorted(threat.get("affected_asset_ids", []))) or "unknown"
        stride = threat.get("category", "Unknown")
        description = threat.get("description", "")
        evidence = threat.get("metadata", {}).get("evidence", {})
        severity = entry.get("severity", "medium")
        confidence = float(entry.get("confidence", 0.8))
        title = threat.get("title", "Untitled")
        mitre_techniques = _extract_finding_mitre(entry)
        stable_key = (
            f"{title}|{asset}|{stride}|{description}|{json.dumps(evidence, sort_keys=True)}"
        )
        fid = hashlib.sha256(stable_key.encode("utf-8")).hexdigest()[:12]
        findings.append(
            {
                "id": f"finding-{fid}",
                "title": title,
                "asset": asset,
                "stride": stride,
                "description": description,
                "evidence": evidence,
                "severity": severity,
                "risk_score": entry.get("risk_score", 0),
                "confidence": round(confidence, 2),
                "mitre_techniques": mitre_techniques,
                "why": entry.get("why", {}),
                "llm_rewritten_description": entry.get("llm_rewritten_description"),
                "llm_mitigations": entry.get("llm_mitigations", []),
            }
        )

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(
        key=lambda f: (
            severity_rank.get(f["severity"], 99),
            f["stride"],
            f["asset"],
            f["title"],
            f["id"],
        )
    )
    return findings


def _extract_finding_mitre(entry: dict) -> list[dict]:
    techniques = entry.get("mitre", {}).get("techniques", [])
    normalized: list[dict] = []
    for technique in techniques:
        tid = technique.get("id")
        name = technique.get("name")
        rationale = technique.get("rationale")
        if not (tid and name and rationale):
            continue
        normalized.append(
            {
                "id": tid,
                "name": name,
                "rationale": rationale,
            }
        )

    normalized.sort(key=lambda item: item["id"])
    return normalized


def _validate_high_critical_mitre_coverage(findings: list[dict]) -> None:
    uncovered = [
        finding["id"]
        for finding in findings
        if finding.get("severity", "").lower() in {"high", "critical"}
        and not finding.get("mitre_techniques")
    ]
    if uncovered:
        raise RuntimeError(
            "Missing MITRE ATT&CK mapping for high/critical findings: " + ", ".join(uncovered)
        )


def _apply_llm_augmentations(scored: dict, llm_insights: dict) -> dict:
    llm_response = llm_insights.get("llm_response") or {}
    augmentations = llm_response.get("finding_augmentations", [])
    by_threat_id = {item.get("threat_id"): item for item in augmentations if item.get("threat_id")}

    enriched_threats = []
    for entry in scored.get("threats", []):
        threat = entry.get("threat", entry)
        threat_id = threat.get("id")
        augmentation = by_threat_id.get(threat_id, {})
        enriched_threats.append(
            {
                **entry,
                "llm_rewritten_description": augmentation.get("rewritten_description"),
                "llm_mitigations": augmentation.get("mitigations", []),
            }
        )

    return {
        **scored,
        "threats": enriched_threats,
        "llm_executive_summary": llm_response.get("executive_summary"),
    }


def _write_llm_artifacts(output_dir: Path, llm_insights: dict) -> None:
    prompt_used = llm_insights.get("prompt_used", "")
    prompt_path = output_dir / "llm_prompt.md"
    prompt_path.write_text(prompt_used)

    prompt_threats_path = output_dir / "llm_prompt_threats.json"
    threats_payload = _extract_prompt_threats(prompt_used)
    has_prompt_threats = threats_payload is not None
    if threats_payload is not None:
        with open(prompt_threats_path, "w") as fh:
            json.dump(threats_payload, fh, indent=2, default=str)

    path = output_dir / "llm_trace.json"
    trace = {
        "model_metadata": llm_insights.get("model_metadata", {}),
        "validated": bool(llm_insights.get("validated", False)),
        "llm_error": llm_insights.get("llm_error"),
        "prompt_file": str(prompt_path.name),
        "prompt_threats_file": (str(prompt_threats_path.name) if has_prompt_threats else None),
    }
    llm_response = llm_insights.get("llm_response") or {}
    trace["executive_summary"] = llm_response.get("executive_summary")
    trace["augmentation_count"] = len(llm_response.get("finding_augmentations", []))
    with open(path, "w") as fh:
        json.dump(trace, fh, indent=2, default=str)


def _extract_prompt_threats(prompt_used: str) -> list[dict] | None:
    match = re.search(
        r"### Threats to Review\n\n(.*?)\n\n### Output Schema",
        prompt_used,
        re.S,
    )
    if not match:
        return None
    block = match.group(1).strip()
    if not block:
        return None
    try:
        parsed = json.loads(block)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list):
        return None
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
