# AI Threat Model

Automated threat model generation from infrastructure-as-code, Kubernetes manifests, and API specifications — powered by STRIDE analysis, MITRE ATT&CK mapping, and LLM-enhanced insights.

## Architecture

```
Input (Compose / K8s / OpenAPI)
  │
  ▼
┌──────────┐    ┌───────────┐    ┌────────────────┐
│ Parsers  │───▶│   Graph   │───▶│ Trust Boundary │
│          │    │ (assets + │    │   Detection    │
│          │    │  flows)   │    └───────┬────────┘
└──────────┘    └───────────┘            │
                                         ▼
                                 ┌───────────────┐
                                 │    STRIDE      │
                                 │   Analysis     │
                                 └───────┬───────┘
                                         │
                              ┌──────────▼──────────┐
                              │   MITRE ATT&CK      │
                              │     Mapping          │
                              └──────────┬──────────┘
                                         │
                              ┌──────────▼──────────┐
                              │   LLM Enrichment    │
                              │  (optional, gated)   │
                              └──────────┬──────────┘
                                         │
                              ┌──────────▼──────────┐
                              │   Risk Scoring      │
                              └──────────┬──────────┘
                                         │
                              ┌──────────▼──────────┐
                              │   Reporting         │
                              │   (PDF + SARIF)     │
                              └─────────────────────┘
```

## Quick Start

```bash
# Clone & install
git clone https://github.com/your-org/ai-threat-model.git
cd ai-threat-model
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run against a Docker Compose file
ai-threat-model examples/docker-compose.yml -t compose -f both

# Run against a K8s manifest (skip LLM)
ai-threat-model examples/k8s-deployment.yaml -t k8s --no-llm

# Run against an OpenAPI spec
ai-threat-model examples/openapi-spec.yaml -t openapi
```

## Project Structure

```
src/
├── cli.py                  # CLI entrypoint
├── parsers/                # Input format parsers
│   ├── compose.py          #   Docker Compose
│   ├── k8s.py              #   Kubernetes manifests
│   └── openapi.py          #   OpenAPI / Swagger specs
├── graph/                  # Unified asset & data-flow graph
│   ├── assets.py           #   Asset node normalisation
│   └── flows.py            #   Data-flow edge inference
├── rules/                  # Threat detection logic
│   ├── trust_boundaries.py #   Trust boundary classification
│   └── stride.py           #   STRIDE templates & matching
├── mitre/                  # MITRE ATT&CK integration
│   ├── mapping.py          #   Threat → technique mapping
│   └── dataset.json        #   ATT&CK technique reference
├── llm/                    # LLM-powered enrichment
│   ├── prompts.py          #   Prompt templates
│   └── guardrails.py       #   Output validation & safety
├── scoring/                # Risk prioritisation
│   └── engine.py           #   Severity + confidence scoring
└── reporting/              # Output generation
    ├── pdf.py              #   PDF report
    └── sarif.py            #   SARIF for CI/CD integration

examples/                   # Sample input files for demo
policies/                   # Scoring & LLM policy configs
tests/                      # Test suite (mirrors src/)
.github/workflows/          # CI pipeline (lint, test, security)
```

## How It Works

1. **Parse** — read Docker Compose, K8s YAML, or OpenAPI specs into a normalised structure.
2. **Graph** — build an in-memory asset graph with data-flow edges inferred from dependencies, selectors, and network topology.
3. **Trust Boundaries** — classify assets into trust zones based on network segmentation, namespace isolation, and public exposure.
4. **STRIDE Analysis** — apply category-specific threat templates to each asset and flag cross-boundary data flows.
5. **MITRE ATT&CK Mapping** — enrich threats with relevant ATT&CK technique IDs and tactic references.
6. **LLM Enrichment** *(optional)* — send the threat model to an LLM for severity refinement, gap analysis, and mitigation suggestions, with output guardrails for safety.
7. **Scoring** — rank threats by risk score (severity × confidence) and filter by policy thresholds.
8. **Reporting** — generate a PDF for human review and/or a SARIF file for GitHub Code Scanning and CI gating.

## Configuration

Edit `policies/default.yaml` to tune scoring weights, severity thresholds, and LLM settings:

```yaml
minimum_severity: low
weights:
  critical: 10.0
  high: 8.0
  medium: 5.0
  low: 2.0
  info: 0.5
ci_gate_severity: high
```

## Testing

```bash
pytest tests/ -v
```

## CI/CD Integration

The included GitHub Actions workflow (`.github/workflows/ci.yml`) runs:

- **Lint** — `ruff check` + `ruff format --check`
- **Test** — `pytest` on Python 3.11 and 3.12
- **Security** — `bandit` static analysis + `safety` dependency audit

SARIF output can be uploaded to GitHub Code Scanning via the `github/codeql-action/upload-sarif` action.

## License

MIT
