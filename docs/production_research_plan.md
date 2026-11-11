# VANTAGE: AppSec evidence and selective repair

## Repository audit and product need

At baseline commit 172b223, VANTAGE contains one rule-based Python agent and CLI, five fixture tests, and research notes. There is no multi-agent runtime, deployed API, or evaluated autonomous cybersecurity platform in this checkout. These are intended capabilities, not demonstrated results.

Target user: an AppSec engineer reviewing pull requests in under-tested Python web/data services. The concrete problem is triaging scanner alerts and deciding whether a proposed mitigation preserves required behavior. A dangerous API call alone does not establish attacker reachability, and removing a warning does not establish a correct fix. Validate this product hypothesis with maintainer interviews and a shadow-mode pilot; measure false alert burden and time to disposition.

## Proposed program-analysis agent

Input: immutable repository snapshot, changed files, optionally SARIF findings, and explicitly permitted pre-change history. Output: typed evidence with source hashes, locations, derivations, supporting and contradicting signals, candidate diffs, and explicit abstention. Treat source files and retrieved documents as untrusted data, including comments containing instructions.

Planned stages:

1. Ingest snapshot and normalize scanner findings.
2. Extract call/data-flow constraints and code idioms.
3. Retrieve analogous fixes from pre-bug history with provenance and license tracking.
4. Generate bounded patch candidates using a model behind a replaceable provider interface.
5. Evaluate candidates against deterministic constraints; preserve conflicting evidence.
6. Rank and abstain using validation-set calibration.
7. Present evidence and diffs for authenticated human review; export an immutable result bundle.

Threat-intelligence and dynamic-testing agents may contribute separate evidence streams. Dynamic validation runs in isolated disposable workers with restricted networking and approved targets. Test-free experiments must exclude dynamic/test evidence from the repairer's context. The evaluator runs separately after outputs are frozen.

## Candidate scientific contribution

Testless repair, mined patches, static-analysis repair, and inferred contracts have prior art. Proposed contribution: dependence-aware evidence fusion and selective repair under oracle scarcity. Group findings by common derivation so multiple signals from one analyzer do not become fake independent votes. Explicitly retain counterevidence. Compare a calibrated ranker against naïve fusion at matched suggestion coverage. Novelty remains provisional pending systematic review.

Primary hypothesis: provenance and disagreement improve precision at fixed coverage on unseen projects. Secondary hypotheses: value transfers across languages and differs between historical developer defects and assistant-modified code. A negative result identifying irreducibly ambiguous behavior is scientifically useful.

## Tools and trade-offs

| Layer | Recommended choice | Reason / constraint |
|---|---|---|
| Initial orchestration | Explicit Python stage interfaces | Small, debuggable baseline; current implementation |
| Durable agent workflow | LangGraph with persistent checkpoints | Introduce for model calls, retries, human interrupts; checkpointing does not itself enforce identity or isolation |
| Static analysis | Semgrep CE plus language-native analysis | Reuse mature rules; review CE/commercial feature and rule licenses; pin engine and rules |
| Python semantics | Python AST, type checker, later cross-file flow analysis | AST rules are cheap but shallow; do not present current sink matching as taint analysis |
| Java extension | CodeQL or a suitable Java analyzer | Evaluate repository/code-use licensing and build requirements before adoption |
| Findings exchange | SARIF 2.1.0 | Established tooling interoperability; current exporter |
| LLM proposals | Provider-neutral structured response adapter | Pin model IDs and prompts, budget candidates/tokens, retain hashes; keep model self-confidence out of correctness labels |
| Storage | PostgreSQL for runs, object storage for artifacts | Add when multi-user durable service exists; avoid unnecessary vector DB initially |
| Retrieval | Versioned Git/AST index with lexical retrieval first | Simple reproducible baseline; add embeddings only if measured benefit exceeds cost |
| Execution | Non-root disposable containers; stronger isolation for untrusted execution | Containers alone are not a complete hostile-code sandbox |
| Delivery | GitHub Actions, container build, environment approval | Current CI builds/tests; deploy only after target and credentials are defined |
| Observability | OpenTelemetry-compatible traces | Record latency, tokens, decisions, retries, policy outcomes; redact secrets and proprietary source |

No framework is scientifically optimal in advance. Compare measured correctness, reproducibility, maintenance burden, and operating cost; adopt additional components only when the pilot requires them.

## Honest benchmark and evaluation

Use pinned Vul4Py artifacts for Python repair experiments after inspecting licenses, environments and labels. Its 2026 preprint describes paired exploit and functional oracles. Add Java/Vul4J only after a Java adapter exists. CVE/fix corpora without functional oracles support retrieval or detection studies but weaker correctness claims.

For strict oracle-scarcity runs: expose vulnerable source and allowed prior history only; withhold tests, issues, CVE descriptions, golden fixes, later commits, and labels. Keep calibrated validation projects separate from test projects. Record any benchmark/model-training contamination that cannot be excluded. Freeze candidates before evaluator-only exploit/regression tests and blinded expert adjudication. Patches passing tests are plausible, not proven correct.

Baselines: abstain-all, current rules, LLM-only with identical code/budget, single evidence channels, naïve fusion, proposed fusion, and a separately labeled test-informed reference. Ablate provenance grouping, contradiction features, historical retrieval, and abstention. Report top-1 correctness, security fixes without regressions, precision/coverage curves, project-clustered uncertainty, costs, and reviewer time. Include every abstention and infrastructure failure. Separate localization-known from end-to-end bug discovery tasks.

AI-modified code needs verifiable assistant provenance. Report controlled assistant-generated tasks separately from naturally occurring bugs. Require independent labeling and do not call injected bugs production defects.

## Delivery stages and acceptance criteria

1. **Current PR:** repository scan, source hashes, SARIF, partial-failure reporting, constrained YAML proposals, unit/CLI checks, CI and container recipe. No real-world effectiveness claim.
2. **Evidence pilot:** add scanner adapter, cross-function evidence and adjudicated positive/negative/ambiguous cases; compare to Semgrep baseline. Stop if alert precision is unusable.
3. **Repair research:** bounded model adapter, versioned retrieval, blinded evaluator and calibrated abstention. Publish frozen protocol and raw per-case outcomes before aggregate claims.
4. **Shadow production:** authenticated API, tenant/repo authorization, queue, persistent run store, cost/time quotas, observability, secret handling, artifact-bound human approvals, and recovery testing. Obtain developer feedback without automatically changing code.
5. **Controlled delivery:** immutable release artifact, vulnerability/dependency scans, pinned dependencies/actions/images, provenance/SBOM, protected environments and measured rollback procedure. Select deployment target before claiming a live production service.

## Primary resources

- Vul4Py preprint: https://arxiv.org/abs/2608.00692
- Getafix: https://doi.org/10.1145/3360585
- Static-analysis-guided repair: https://doi.org/10.1145/3611643.3616363
- Proof2Fix: https://se.inf.ethz.ch/old/people/meyer/publications/proofs/execution_free_program_repair-FSE-2024.pdf
- Semgrep CE: https://semgrep.dev/products/community-edition/
- LangGraph interrupts: https://reference.langchain.com/python/langgraph/types/interrupt

These sources motivate engineering choices and experiments; they do not establish this system's novelty or effectiveness.
