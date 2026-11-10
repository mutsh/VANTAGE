# VANTAGE Evidence-Guided Repair: Research and Evaluation

## Research positioning

The agent addresses a real security-review problem: risky code patterns may be present in AI-assisted or legacy changes, while maintainers do not always have an executable reproducer or complete specification. VANTAGE's first agent provides reviewable, source-linked evidence and cautious mitigations.

Do not claim that test-free repair is new. Prior work includes code-inferred state abstractions (JAID), exploit-guided vulnerability repair (ExtractFix / Beyond Tests), static-analysis-guided repair, mined fix patterns (Getafix), and prover-based source-only repair (Proof2Fix). A defensible research contribution to investigate is whether **provenance-preserving evidence, explicit counterevidence, and calibrated abstention** improve reviewer trust and patch correctness under oracle scarcity. This is a hypothesis pending a systematic related-work review.

## Research questions

- **RQ1:** Which source-code evidence best predicts whether a security finding is reachable and actionable when tests and issue reports are unavailable?
- **RQ2:** Does provenance-aware evidence fusion improve patch correctness at fixed recommendation coverage over LLM-only, rule-only, single-channel, and unweighted-fusion baselines?
- **RQ3:** Does explicit abstention reduce incorrect accepted security patches, and what coverage trade-off does it impose?
- **RQ4:** Do performance and calibration differ for developer-authored versus AI-assistant-modified code, across projects and languages?

## Evidence channels to add

1. **Static sink/source analysis:** identify source-to-sink paths, sanitizer use, and control/data-flow constraints. The current MVP detects sinks only and does not establish taint.
2. **Repository consistency:** inspect callers, wrappers, validators, type hints, and neighboring functions for constraints or counterexamples.
3. **Pre-fix history patterns:** retrieve prior human fixes, strictly limiting the index to commits before the target bug/fix.
4. **External security intelligence:** optionally add versioned advisory/CVE evidence as a separate channel; record source, date, and package/version match. Never silently mix this with source-derived evidence.

Evidence from one underlying analyzer must not be counted as independent votes. Store provenance, derivation, line spans, modality, polarity, uncertainty, and limitations. Retain disagreement.

## Benchmark protocol

### Data

- Use **Vul4Py** as the first Python repair benchmark candidate. Its paper describes paired exploit and project-native functional oracles for each entry; tests remain evaluator-only in VANTAGE's test-free repair condition. Review the released artifact, licenses, exact benchmark version, and execution setup before committing to a final sample.
- Use **Vul4J** and **VJBench** when adding a Java adapter. Both are repair-oriented Java vulnerability datasets; Vul4J includes reproducible vulnerabilities and proof-of-vulnerability tests. Pin versions and document exclusions.
- Include **BugsInPy** and **Defects4J** for general historical defects only if the research claim includes non-security bugs; keep these results separate from vulnerability repair.
- Create an AI-assistant-modified stratum with verifiable provenance and independent human adjudication. If changes are generated in a controlled study, label them controlled/generated and do not present them as naturally occurring production bugs.

### Oracle separation

For the repair condition, provide only the vulnerable code snapshot and explicitly allowed pre-fix repository context. Withhold tests, issue text, vulnerability descriptions, fix commits, post-fix history, and labels. Freeze output patches and evidence ledgers before an evaluator sees held-out tests or gold fixes. The evaluator may then use hidden tests, patch comparison, security analysis, and blinded human review. Without an independent evaluation oracle, report only evidence-detection performance, not patch correctness.

### Baselines

- No recommendation / abstention.
- LLM-only with equal code context and candidate budget.
- Rule/static-analysis only.
- Each evidence channel alone.
- Naïve unweighted evidence fusion.
- Provenance-aware, disagreement-sensitive fusion plus calibrated abstention.
- Test-driven repair as a separately labeled reference condition, never as the test-free condition.

Control model/version, prompt, temperature, candidate count, token budget, tools, and execution permissions. Fit thresholds on validation projects only; freeze before test evaluation. Split by project and preferably by time to reduce leakage.

### Outcomes

- Confirmed vulnerability fixes / cases attempted and / total cases.
- Precision of accepted suggestions; plausible-but-incorrect rate.
- Selective risk versus coverage, including precision at predeclared coverage and risk-coverage curves.
- Vulnerability localization recall@k, patch size, regression rate, compilation/static-check results, runtime, cost, and reviewer time.
- Security expert rating of evidence relevance, unsupported assertions, patch scope, and usefulness; blind raters to system condition and report agreement.
- Stratify by language, CWE/bug class, project, severity, and code authorship provenance. Report confidence intervals clustered by project, all abstentions, and all exclusions.

Never treat passing available tests, exact patch matching, a static warning disappearing, or an LLM judge as proof of security correctness.

## Current evaluation status

The tests in this repository are small unit fixtures. They validate that selected AST patterns are reported with locations and that the agent abstains from claiming security when none are found. They do not establish precision, recall, exploitability, patch correctness, or generalization. The current implementation generates no patch and has no benchmark result.
