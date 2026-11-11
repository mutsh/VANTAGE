# VANTAGE — Vulnerability Assessment and Testing Automation for Global Enhancements

**Evidence-guided security repair agent**

VANTAGE is an agent-oriented security research project. Its first runnable component is a conservative Python source analyzer that turns suspicious code patterns into traceable evidence and mitigation guidance. It does not change source files, claim that a finding is exploitable, or pretend that a suggested mitigation is proven correct.

## Evidence-Guided Repair Agent (MVP)

The agent currently inspects a Python file for high-risk patterns: dynamic `eval`/`exec`, unsafe pickle loading, subprocess shell execution, SQL strings built with interpolation, and unsafe PyYAML loading. Each finding includes a source location, code excerpt, rationale, suggested remediation, and limits of the analysis. For one simple YAML loader call, it can also emit a unified diff proposal using `yaml.safe_load`; it never applies that proposal.

The agent is deliberately **human-gated**. Static evidence can identify a risky sink, but this MVP does not perform taint analysis or know whether data is attacker-controlled. It therefore returns a narrow, reviewable patch proposal only for a simple YAML loader case and review guidance for other findings.

## Quick start

Requires Python 3.10+. No runtime dependencies are needed.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .

vantage repair-analyze --file path/to/module.py
```

JSON output:

```bash
vantage repair-analyze --file path/to/module.py --format json
```

Exit codes: `0` means analysis completed (findings may be present); `2` means the file could not be analyzed.

## Design principles

- Preserve source provenance for every evidence item.
- Separate a risky code pattern from a confirmed vulnerability.
- Include counterevidence and limitations instead of inventing certainty.
- Never edit source automatically; patch proposals are reviewable diffs and require explicit human approval before application.
- Evaluate repair proposals with hidden tests and independent human review, while keeping those oracles out of the agent's repair context.

## Current limits

This is a research MVP, not a production security scanner. It supports Python AST patterns only, does not track tainted data across functions or files, does not mine repository history, and has not been evaluated on a real vulnerability benchmark. Patch proposals are limited and require human review. The included tests validate behavior on small fixtures only.

## Project map

- `src/vantage/agents/evidence_repair.py` — agent API and report assembly
- `src/vantage/analysis/python_security.py` — static evidence extractors
- `src/vantage/cli.py` — command-line interface
- `tests/` — focused unit fixtures
- `docs/research_and_evaluation.md` — research framing, novelty limits, and benchmark plan

## Development

```bash
python -m unittest discover -s tests -v
```

Before describing any output as a correct repair, use the benchmark protocol in [`docs/research_and_evaluation.md`](docs/research_and_evaluation.md). A detector smoke test is not a security benchmark.

## Repository scanning and delivery foundation (v0.2)

```bash
vantage scan --repo ./service --format json > report.json
vantage scan --repo ./service --format sarif > report.sarif
```

Scans include Python source hashes and visible per-file errors. Test/build/dependency directories and symlinks are excluded. An incomplete scan exits with code 2; findings themselves do not change the exit code. No findings is not a security verdict. YAML proposals are restricted to simple single-line calls with exactly one positional argument and no keywords; other loader signatures require manual remediation.

CI checks supported Python versions and builds a non-root container. To run against your own checkout:

```bash
docker build -t vantage:local .
docker run --rm --network none --read-only --cap-drop ALL -v "$PWD:/repo:ro" vantage:local scan --repo /repo --format sarif
```

The container build is a delivery recipe, not a deployed service. Dependency/action/image pinning and platform-specific approvals remain release prerequisites. See [the production and research plan](docs/production_research_plan.md) for the AppSec use case, multi-agent architecture, framework choices, scientific hypotheses, and staged acceptance criteria.

## Run the local multi-agent workflow

See [Run on your PC](docs/run_on_pc.md) for Windows PowerShell and Linux/macOS setup, the dynamic demo, worker limits, and optional local Ollama repair proposals.

```bash
vantage run --repo examples/yaml_demo --dynamic --output demo-report.json
```

Build `docker/Dockerfile.worker` as `vantage-worker:local` first. The workflow freezes proposals before running evaluator-only security and functional suites in separate containers. It never changes the original repository. This extends the static agent: dynamic execution is opt-in and unavailable evidence remains unverified. The default repair baseline is deterministic; `--model` adds a locally hosted model without cloud API keys. The previous sections describe the narrower static-only commands.
