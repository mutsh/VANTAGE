"""Local multi-agent workflow with frozen proposals and evaluator-only tests."""
from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from vantage.dynamic import DynamicEvidenceAgent
from vantage.local_model import LocalModelRepairAgent
from vantage.pipeline import scan_repository


def snapshot_repository(root: Path, destination: Path) -> str:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Repository must be a directory')
    manifest = []
    total = 0
    excluded = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'build', 'dist', '.ssh', '.aws', '.azure', '.kube'}
    for source in sorted(root.rglob('*')):
        relative = source.relative_to(root)
        if any(part in excluded or part == '.env' or part.startswith('.env.') for part in relative.parts):
            continue
        if any(p.is_symlink() for p in [source, *source.parents] if p != root):
            continue
        if not source.is_file():
            continue
        size = source.stat().st_size
        total += size
        if size > 5_000_000 or total > 50_000_000 or len(manifest) >= 5000:
            raise ValueError('Local snapshot limit exceeded (5 MB/file, 50 MB total, 5000 files)')
        content = source.read_bytes()
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        manifest.append((relative.as_posix(), hashlib.sha256(content).hexdigest()))
    return hashlib.sha256(json.dumps(manifest).encode()).hexdigest()


def apply_candidate(root: Path, relative: str, diff: str) -> None:
    """Apply a generated single-file unified diff with exact context checks."""
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError('Candidate path escapes snapshot or is missing')
    original = path.read_text(encoding='utf-8').splitlines(keepends=True)
    lines = diff.splitlines(keepends=True)
    if len(lines) < 3 or lines[0].rstrip() != f'--- a/{relative}' or lines[1].rstrip() != f'+++ b/{relative}':
        raise ValueError('Candidate must modify the recorded file only')
    result, cursor, i = [], 0, 2
    while i < len(lines):
        match = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n?', lines[i])
        if not match:
            raise ValueError('Malformed diff hunk')
        start = int(match.group(1)) - 1
        if start < cursor or start > len(original):
            raise ValueError('Invalid diff position')
        result.extend(original[cursor:start]); cursor = start; i += 1
        old_count = new_count = 0
        while i < len(lines) and not lines[i].startswith('@@ '):
            line = lines[i]
            if line[0] not in ' +-':
                raise ValueError('Unsupported diff line')
            if line[0] in ' -':
                if cursor >= len(original) or original[cursor] != line[1:]:
                    raise ValueError('Source differs from candidate context')
                cursor += 1; old_count += 1
            if line[0] in ' +':
                result.append(line[1:]); new_count += 1
            i += 1
        if old_count != int(match.group(2) or 1) or new_count != int(match.group(4) or 1):
            raise ValueError('Diff count mismatch')
    result.extend(original[cursor:])
    path.write_text(''.join(result), encoding='utf-8')


class ReviewAgent:
    def decide(self, baseline: dict | None, candidate: dict | None) -> str:
        if not baseline or not candidate:
            return 'unverified'
        b, c = baseline.get('suites', {}), candidate.get('suites', {})
        if baseline.get('status') != 'completed' or candidate.get('status') != 'completed':
            return 'unverified'
        if c['functional']['status'] == 'failed':
            return 'rejected_functional_regression'
        if c['security']['status'] == 'failed':
            return 'rejected_security_check'
        if b['functional']['status'] == 'passed' and b['security']['status'] == 'failed':
            return 'plausible_repair_human_review_required'
        return 'inconclusive_baseline'


class MultiAgentWorkflow:
    """Deterministic specialist agents; no cloud keys or LLM required."""
    def run(self, repo: Path, dynamic: bool = False, image: str = 'vantage-worker:local', timeout: int = 60, model: str | None = None) -> dict:
        events = []
        def event(agent: str, status: str):
            events.append({'agent': agent, 'status': status, 'time': datetime.now(timezone.utc).isoformat()})
        with tempfile.TemporaryDirectory(prefix='vantage-run-') as directory:
            workspace = Path(directory)
            baseline_root = workspace / 'baseline'; baseline_root.mkdir()
            fingerprint = snapshot_repository(repo, baseline_root)
            event('intake', 'snapshot_frozen')
            scan = scan_repository(baseline_root)
            event('static_analysis', scan['status'])
            candidates = []
            for report in scan['reports']:
                for proposal in report['report']['patch_proposals']:
                    candidates.append({'file': report['file'], 'proposal': proposal})
            model_error = None
            if model:
                try:
                    candidates.extend(LocalModelRepairAgent().propose(model, baseline_root, scan))
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    model_error = str(exc)
            # This stage is completed before dynamic results exist.
            event('repair_planner', f'{len(candidates)}_candidates_frozen')
            evaluator = DynamicEvidenceAgent(image, timeout)
            baseline = evaluator.evaluate(baseline_root) if dynamic else None
            event('dynamic_evidence', baseline['status'] if baseline else 'not_requested')
            outcomes = []
            for index, item in enumerate(candidates[:10]):
                candidate_root = workspace / f'candidate-{index}'
                shutil.copytree(baseline_root, candidate_root)
                try:
                    apply_candidate(candidate_root, item['file'], item['proposal']['patch'])
                    ast.parse((candidate_root / item['file']).read_text(encoding='utf-8'))
                    evidence = evaluator.evaluate(candidate_root) if dynamic else None
                    decision = ReviewAgent().decide(baseline, evidence)
                    outcomes.append({**item, 'dynamic': evidence, 'decision': decision})
                except (ValueError, OSError, SyntaxError) as exc:
                    outcomes.append({**item, 'decision': 'invalid_candidate', 'error': str(exc)})
            event('review', 'completed')
            incomplete = bool(model_error) or len(candidates) > 10 or scan['status'] != 'completed' or (dynamic and (not baseline or baseline['status'] != 'completed'))
            if dynamic and any(c['decision'] in {'unverified', 'invalid_candidate'} for c in outcomes):
                incomplete = True
            event('reporting', 'completed')
            return {'schema_version': '0.3', 'status': 'incomplete' if incomplete else 'completed',
                    'snapshot_sha256': fingerprint, 'events': events, 'static': scan,
                    'baseline_dynamic': baseline, 'candidates': outcomes,
                    'candidate_limit': 10, 'candidates_not_evaluated': max(0, len(candidates) - 10),
                    'research_mode': 'proposals_frozen_before_dynamic_evaluation',
                    'implementation': 'specialist workflow with optional local model proposer',
                    'model': model, 'model_error': model_error,
                    'source_modified': False,
                    'interpretation': 'Passing checks supports a plausible repair, not proof of correctness.'}
