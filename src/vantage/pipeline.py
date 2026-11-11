"""Repository analysis without importing or executing target source."""
from __future__ import annotations

import hashlib
from pathlib import Path

from vantage.agents.evidence_repair import EvidenceRepairAgent
from vantage.analysis.python_security import SourceAnalysisError

EXCLUDED = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'build', 'dist', 'tests'}


def scan_repository(root: Path) -> dict:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Repository root must be a directory')
    reports, errors = [], []
    for path in sorted(root.rglob('*.py')):
        relative = path.relative_to(root)
        if any(part in EXCLUDED for part in relative.parts):
            continue
        # Skip symlink files and directories, including links inside the root.
        if any(parent.is_symlink() for parent in [path, *path.parents] if parent != root):
            continue
        try:
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            report = EvidenceRepairAgent().analyze(path, root).to_dict()
            after = hashlib.sha256(path.read_bytes()).hexdigest()
            if before != after:
                raise ValueError('Source changed during analysis; rerun on an immutable checkout')
            reports.append({'file': relative.as_posix(), 'source_sha256': before, 'report': report})
        except (OSError, UnicodeError, SourceAnalysisError, ValueError) as exc:
            errors.append({'file': relative.as_posix(), 'error': str(exc)})
    return {
        'schema_version': '0.2', 'tool': 'vantage',
        'status': 'incomplete' if errors else 'completed',
        'files_analyzed': len(reports), 'reports': reports, 'errors': errors,
        'policy': {'source_execution': False, 'patch_application': False,
                   'excluded_directories': sorted(EXCLUDED)},
    }


def to_sarif(scan: dict) -> dict:
    results = []
    for item in scan['reports']:
        for finding in item['report']['findings']:
            results.append({
                'ruleId': finding['rule_id'], 'level': 'warning',
                'message': {'text': finding['claim'] + ' ' + finding['limitations']},
                'locations': [{'physicalLocation': {
                    'artifactLocation': {'uri': item['file']},
                    'region': {'startLine': finding['line']}}}],
                'properties': {'source_sha256': item['source_sha256'], 'confirmed_vulnerability': False},
            })
    notifications = [{'level': 'error', 'message': {'text': e['file'] + ': ' + e['error']}} for e in scan['errors']]
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
            'runs': [{'tool': {'driver': {'name': 'VANTAGE', 'version': '0.2.0'}},
                      'results': results,
                      'invocations': [{'executionSuccessful': not scan['errors'],
                                       'toolExecutionNotifications': notifications}]}]}
