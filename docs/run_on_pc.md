# Run VANTAGE on your PC

## Windows (PowerShell)

Install Git, Python 3.10 or newer, and Docker Desktop. Start Docker Desktop with Linux containers enabled. No GPU, model download, API key, or cloud account is needed for the current deterministic agents.

```powershell
git clone --branch feature/evidence-analysis-delivery https://github.com/mutsh/VANTAGE.git
cd VANTAGE
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
docker build -f docker/Dockerfile.worker -t vantage-worker:local .
.\.venv\Scripts\vantage.exe run --repo examples/yaml_demo --dynamic --output demo-report.json
Get-Content demo-report.json
```

The image build downloads Python and pinned PyYAML dependencies. Subsequent evaluation runs have networking disabled. If Docker is absent, stopped, or the image is missing, dynamic evidence is recorded as unavailable and the run exits with code 2; it does not execute test code directly on your PC.

## Linux/macOS

```bash
git clone --branch feature/evidence-analysis-delivery https://github.com/mutsh/VANTAGE.git
cd VANTAGE
python3 -m venv .venv
.venv/bin/python -m pip install -e .
docker build -f docker/Dockerfile.worker -t vantage-worker:local .
.venv/bin/vantage run --repo examples/yaml_demo --dynamic --output demo-report.json
```

## Analyze your own repository

Static-only mode does not execute repository code:

```powershell
.\.venv\Scripts\vantage.exe run --repo C:\projects\my-service --output my-service-report.json
```

For dynamic mode, provide two evaluator suites under the target's `tests` directory: `test_functional*.py` for preserved behavior and `test_security*.py` for the security property. Tests use Python unittest discovery. Build a custom worker image containing the target's pinned dependencies, then pass `--image my-worker:local`. VANTAGE does not install the target's dependencies or build scripts on your host. Write reports outside the target repository.

```powershell
.\.venv\Scripts\vantage.exe run --repo C:\projects\my-service --dynamic --image my-worker:local --timeout 60 --output my-service-report.json
```

The demo should show baseline functional success, baseline security failure, and both suites passing for the proposed YAML change. Until actually executed in your environment, this is an expected outcome rather than a reported benchmark result. A zero-test suite, timeout, infrastructure failure, or missing worker remains unverified.

## Agents and evidence

The local coordinator invokes six deterministic specialist agents/stages: intake snapshot, static analysis, repair planning, Docker dynamic evaluation, review, and report generation. This is a working bounded workflow, not six independently reasoning LLMs. Proposals currently cover only simple YAML loader changes. Other findings require developer reasoning; no automatic general-purpose repair is claimed.

Candidates are frozen before dynamic results are available. Each is evaluated in a separate snapshot; the original repository is never patched. A candidate is labeled plausible only when baseline functionality passes, baseline security fails, and both candidate suites pass. Human review is still required. Tests alone cannot prove semantic correctness, and target-controlled tests/logs must not be trusted as independent research labels.

Workers run without networking, as a non-root user, with a read-only root/source mount, dropped capabilities, process/memory/CPU limits, timeout, and temporary storage. Common credential directories and `.env` files are omitted from snapshots. Containers share a kernel: use this local runner for trusted repositories and approved tests; hostile samples belong in a disposable VM or stronger sandbox. Use Docker Desktop/rootless Docker as appropriate; the coordinator itself requires Docker access and must not be exposed as an unauthenticated service.

Run limits: 5 MB per file, 50 MB snapshot, 5000 files, ten candidates, 1–600 seconds per suite. Dependency installation and image digest pinning are explicit operator responsibilities. The report records the actual worker image content ID. No port is exposed and no production system is probed.

## Optional local AI repair agent

Install Ollama separately and download a coding model suitable for your RAM/VRAM. Keep the Ollama server running on its default loopback address. Use the exact installed model name shown by `ollama list`:

```powershell
ollama list
.\.venv\Scripts\vantage.exe run --repo C:\projects\my-service --model YOUR_INSTALLED_MODEL --dynamic --image my-worker:local --output ai-report.json
```

Only source files with current static findings are sent to the local server; the repair prompt excludes test files. The local model can propose at most three single-file diffs, which are checked against exact source context and Python syntax before dynamic evaluation. It has no shell or tool access. A malformed response or unavailable server is an explicit incomplete run. For research, record model weights/digest and settings as well as the reported model name; model tags are mutable. This optional adapter has contract tests but needs a live model smoke run on your PC.
