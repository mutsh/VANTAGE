# VANTAGE

**Vulnerability Assessment and Threat Intelligence with Evidence-Guided Repair**

VANTAGE is an agent-oriented security research project. Its first runnable component is a conservative Python source analyzer that turns suspicious code patterns into traceable evidence and mitigation guidance. It does not change source files, claim that a finding is exploitable, or pretend that a suggested mitigation is proven correct.

## Evidence-Guided Repair Agent (MVP)

The agent currently inspects a Python file for high-risk patterns: dynamic `eval`/`exec`, unsafe pickle loading, subprocess shell execution, SQL strings built with interpolation, and unsafe PyYAML loading. Each finding includes a source location, code excerpt, evidence type, rationale, suggested remediation, and limits of the analysis.

The agent is deliberately **human-gated and read-only**. Static evidence can identify a risky sink, but this MVP does not perform taint analysis or know whether data is attacker-controlled. It therefore returns review guidance instead of silently rewriting code.

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
- Keep analysis read-only; a future patch generator must return a reviewable diff and require explicit human approval before application.
- Evaluate repair proposals with hidden tests and independent human review, while keeping those oracles out of the agent's repair context.

## Current limits

This is a research MVP, not a production security scanner. It supports Python AST patterns only, does not track tainted data across functions or files, does not mine repository history, does not generate patches, and has not been evaluated on a real vulnerability benchmark. The included tests validate detector behavior on small fixtures only.

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
