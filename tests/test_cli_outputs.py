"""CLI output integration tests."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from src.cli import main


def test_cli_writes_findings_json(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    example = root / "examples" / "docker-compose.yml"
    output_dir = tmp_path / "outputs"
    report_base = tmp_path / "report"

    exit_code = main(
        [
            str(example),
            "-t",
            "compose",
            "--no-llm",
            "-f",
            "sarif",
            "--output-dir",
            str(output_dir),
            "-o",
            str(report_base),
        ]
    )

    assert exit_code == 0

    findings_path = output_dir / "findings.json"
    assert findings_path.exists()

    with open(findings_path) as fh:
        findings = json.load(fh)

    assert isinstance(findings, list)
    assert len(findings) > 0
    required = {
        "id",
        "title",
        "asset",
        "stride",
        "description",
        "evidence",
        "severity",
        "risk_score",
        "confidence",
        "mitre_techniques",
        "why",
        "llm_rewritten_description",
        "llm_mitigations",
    }
    assert required.issubset(findings[0].keys())
    assert isinstance(findings[0]["mitre_techniques"], list)
    assert isinstance(findings[0]["why"], dict)
    assert isinstance(findings[0]["llm_mitigations"], list)


def test_cli_findings_are_repeatable(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    example = root / "examples" / "docker-compose.yml"
    output_dir = tmp_path / "outputs"
    report_base = tmp_path / "report"

    args = [
        str(example),
        "-t",
        "compose",
        "--no-llm",
        "-f",
        "sarif",
        "--output-dir",
        str(output_dir),
        "-o",
        str(report_base),
    ]
    assert main(args) == 0
    first = json.loads((output_dir / "findings.json").read_text())
    assert main(args) == 0
    second = json.loads((output_dir / "findings.json").read_text())
    assert first == second


def test_cli_high_critical_have_mitre_coverage(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    example = root / "examples" / "docker-compose.yml"
    output_dir = tmp_path / "outputs"
    report_base = tmp_path / "report"

    exit_code = main(
        [
            str(example),
            "-t",
            "compose",
            "--no-llm",
            "-f",
            "sarif",
            "--output-dir",
            str(output_dir),
            "-o",
            str(report_base),
        ]
    )
    assert exit_code == 0

    findings = json.loads((output_dir / "findings.json").read_text())
    high_critical = [
        finding
        for finding in findings
        if finding.get("severity", "").lower() in {"high", "critical"}
    ]
    assert high_critical
    assert all(finding.get("mitre_techniques") for finding in high_critical)
    assert all(
        {"id", "name", "rationale"}.issubset(technique.keys())
        for finding in high_critical
        for technique in finding.get("mitre_techniques", [])
    )


def test_cli_policy_gate_fails_with_strict_threshold(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    example = root / "examples" / "docker-compose.yml"
    output_dir = tmp_path / "outputs"
    report_base = tmp_path / "report"
    policy = tmp_path / "strict.yml"
    policy.write_text(
        "minimum_score_to_report: 0\nbuild:\n  fail_on_score_gte: 1\n  allowlist_patterns: []\n"
    )

    exit_code = main(
        [
            str(example),
            "-t",
            "compose",
            "--no-llm",
            "-f",
            "sarif",
            "--policy",
            str(policy),
            "--output-dir",
            str(output_dir),
            "-o",
            str(report_base),
        ]
    )
    assert exit_code == 2


def test_cli_policy_gate_passes_with_allowlist(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    example = root / "examples" / "docker-compose.yml"
    output_dir = tmp_path / "outputs"
    report_base = tmp_path / "report"
    policy = tmp_path / "allowlist.yml"
    policy.write_text(
        "minimum_score_to_report: 0\n"
        "build:\n"
        "  fail_on_score_gte: 1\n"
        "  allowlist_patterns:\n"
        "    - '^threat:.*$'\n"
    )

    exit_code = main(
        [
            str(example),
            "-t",
            "compose",
            "--no-llm",
            "-f",
            "sarif",
            "--policy",
            str(policy),
            "--output-dir",
            str(output_dir),
            "-o",
            str(report_base),
        ]
    )
    assert exit_code == 0


def test_cli_no_llm_still_outputs_full_findings(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    example = root / "examples" / "docker-compose.yml"
    output_dir = tmp_path / "outputs"
    report_base = tmp_path / "report"

    exit_code = main(
        [
            str(example),
            "-t",
            "compose",
            "--no-llm",
            "-f",
            "sarif",
            "--output-dir",
            str(output_dir),
            "-o",
            str(report_base),
        ]
    )
    assert exit_code == 0

    findings = json.loads((output_dir / "findings.json").read_text())
    assert findings
    assert all("description" in finding and finding["description"] for finding in findings)
    assert all("evidence" in finding for finding in findings)
    assert all("llm_mitigations" in finding for finding in findings)


def test_cli_llm_adds_fields_and_writes_trace(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    example = root / "examples" / "docker-compose.yml"
    output_dir = tmp_path / "outputs"
    report_base = tmp_path / "report"

    fake_llm_payload = {
        "prompt_used": (
            "## Threat Model Context\n\n"
            "**Assets:** 1\n**Data Flows:** N/A\n**Trust Boundaries:** N/A\n"
            "**Preliminary Threats:** 1\n\n"
            "### Threats to Review\n\n"
            "[\n"
            '  {"threat": {"id": "threat:compose:service:api:Spoofing"}}\n'
            "]\n\n"
            "### Output Schema\n\n"
            "Return ONLY valid JSON (no markdown fences) matching:\n{}"
        ),
        "model_metadata": {"model": "test-model", "prompt_sha256": "abc123"},
        "llm_response": {
            "executive_summary": "Key risk: exposed internet-facing paths.",
            "finding_augmentations": [
                {
                    "threat_id": "threat:compose:service:api:Spoofing",
                    "rewritten_description": (
                        "The api service may be impersonated when strong "
                        "identity checks are missing."
                    ),
                    "mitigations": [
                        {
                            "priority": "high",
                            "action": "Require strong mutual authentication for service identity.",
                            "rationale": "Reduces spoofing opportunities from external actors.",
                        }
                    ],
                }
            ],
        },
        "raw": {},
        "validated": True,
    }

    with patch("src.cli.PromptEngine.enrich", return_value=fake_llm_payload):
        with patch("src.cli.OutputGuardrail.validate", side_effect=lambda x: x):
            exit_code = main(
                [
                    str(example),
                    "-t",
                    "compose",
                    "-f",
                    "sarif",
                    "--output-dir",
                    str(output_dir),
                    "-o",
                    str(report_base),
                ]
            )

    assert exit_code == 0
    findings = json.loads((output_dir / "findings.json").read_text())
    api_spoofing = [
        finding
        for finding in findings
        if finding["title"] == "Service identity spoofing"
        and "compose:service:api" in finding["asset"]
    ]
    assert api_spoofing
    assert api_spoofing[0]["llm_rewritten_description"]
    assert api_spoofing[0]["llm_mitigations"]

    trace = json.loads((output_dir / "llm_trace.json").read_text())
    assert trace["model_metadata"]["model"] == "test-model"
    assert trace["prompt_file"] == "llm_prompt.md"
    assert trace["prompt_threats_file"] == "llm_prompt_threats.json"
    assert (output_dir / "llm_prompt.md").exists()
    assert (output_dir / "llm_prompt_threats.json").exists()
