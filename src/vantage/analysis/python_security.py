"""Conservative Python AST rules that collect security-relevant evidence.

These rules identify risky constructs, not exploitable vulnerabilities. They
do not perform taint analysis, path-sensitive reasoning, or interprocedural
data-flow analysis.
"""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    polarity: str
    title: str
    claim: str
    file: str
    line: int
    excerpt: str
    remediation: str
    limitations: str

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


class SourceAnalysisError(ValueError):
    """Raised when source cannot be safely parsed."""


def _excerpt(lines: list[str], line: int) -> str:
    return lines[line - 1].strip() if 1 <= line <= len(lines) else ""


def _name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _is_interpolated(node: ast.expr) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(item, ast.FormattedValue) for item in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "format_map"}:
        return True
    return False


def analyze_python_source(source: str, filename: str = "<memory>") -> list[Finding]:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        raise SourceAnalysisError(f"Python syntax error at line {exc.lineno}: {exc.msg}") from exc

    lines = source.splitlines()
    findings: list[Finding] = []

    def add(node: ast.AST, rule_id: str, category: str, title: str, claim: str, remediation: str, limitations: str) -> None:
        line = getattr(node, "lineno", 1)
        findings.append(Finding(
            rule_id=rule_id,
            category=category,
            polarity="risk_signal",
            title=title,
            claim=claim,
            file=filename,
            line=line,
            excerpt=_excerpt(lines, line),
            remediation=remediation,
            limitations=limitations,
        ))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = _name(node.func)
            leaf = called.rsplit(".", 1)[-1]

            if leaf in {"eval", "exec"}:
                add(
                    node, "PYSEC-DYN-001", "dynamic_code_execution",
                    f"Dynamic code execution via `{leaf}`",
                    f"The source calls `{leaf}`; the analyzer cannot determine whether its argument is attacker-controlled.",
                    "Avoid evaluating input as code. If the input represents data, use a constrained data format (for example JSON) or `ast.literal_eval` only when Python literal syntax is explicitly intended.",
                    "This is a sink observation, not proof of an exploitable injection. Source provenance and data flow are not analyzed.",
                )

            if called in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"}:
                add(
                    node, "PYSEC-SER-001", "unsafe_deserialization",
                    "Pickle deserialization",
                    "The source deserializes pickle data; Python pickle can execute code during loading if the payload is untrusted.",
                    "Do not load untrusted pickle data. Prefer a non-executable format or a serialization design with authenticity and strict validation.",
                    "The analyzer does not establish whether the serialized bytes are trusted or authenticated.",
                )

            if called.startswith("subprocess.") and any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
                add(
                    node, "PYSEC-SHELL-001", "command_injection",
                    "Subprocess invoked with `shell=True`",
                    "Shell interpretation is enabled; risk depends on whether command text includes untrusted data and how it is constructed.",
                    "Prefer an argument list with `shell=False`; keep the executable fixed and pass variable values as separate arguments. Preserve shell behavior only when it is required and inputs are safely constrained.",
                    "The analyzer does not trace command arguments to their sources and cannot determine exploitability.",
                )

            if leaf == "execute" and node.args and _is_interpolated(node.args[0]):
                add(
                    node, "PYSEC-SQL-001", "sql_injection",
                    "Interpolated string passed to `execute`",
                    "The first argument to a method named `execute` is constructed with interpolation or formatting; this may be unsafe SQL construction.",
                    "Use the database driver's parameter binding API and its placeholder syntax instead of embedding values in the query string.",
                    "The receiver is not verified to be a database cursor and the analyzer does not trace values or identify the database driver.",
                )

            if called in {"yaml.load", "yaml.full_load", "yaml.unsafe_load"}:
                safe_loader = any(keyword.arg == "Loader" and _name(keyword.value).endswith("SafeLoader") for keyword in node.keywords)
                if not safe_loader:
                    add(
                        node, "PYSEC-YAML-001", "unsafe_deserialization",
                        f"Potentially unsafe YAML loader `{called}`",
                        "A YAML loading function is used without a visibly specified SafeLoader.",
                        "Use `yaml.safe_load` for data-only YAML when compatible with the application's required types.",
                        "The project may require custom YAML types; input trust and PyYAML version are not checked.",
                    )

    findings.sort(key=lambda item: (item.line, item.rule_id))
    return findings


def analyze_python_file(path: Path, repo_root: Path | None = None) -> list[Finding]:
    path = path.resolve()
    root = (repo_root or path.parent).resolve()
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise SourceAnalysisError("The source file must be inside the supplied repository root.") from exc
    return analyze_python_source(path.read_text(encoding="utf-8"), relative)
