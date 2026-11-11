"""Explicitly requested dynamic evidence in disposable Docker workers."""
from __future__ import annotations

import re
import shutil
import subprocess
import threading
import uuid
from pathlib import Path


class DynamicEvidenceAgent:
    def __init__(self, image: str = 'vantage-worker:local', timeout: int = 60):
        if timeout < 1 or timeout > 600:
            raise ValueError('Timeout must be between 1 and 600 seconds')
        if not image or image.startswith('-'):
            raise ValueError('Invalid worker image')
        self.image, self.timeout = image, timeout

    def evaluate(self, snapshot: Path) -> dict:
        if not shutil.which('docker'):
            return {'status': 'unavailable', 'reason': 'Docker CLI is not installed', 'suites': {}}
        try:
            inspect = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', self.image],
                                     capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {'status': 'unavailable', 'reason': str(exc), 'suites': {}}
        if inspect.returncode:
            return {'status': 'unavailable', 'reason': 'Start Docker and build the worker image first', 'suites': {}}
        # Resolve to a content ID so a mutable tag cannot change between suites.
        image_id = inspect.stdout.strip()
        suites = {name: self._suite(snapshot, image_id, pattern)
                  for name, pattern in [('functional', 'test_functional*.py'), ('security', 'test_security*.py')]}
        return {'status': 'completed' if all(s['status'] in {'passed', 'failed'} for s in suites.values()) else 'incomplete',
                'image_id': image_id, 'suites': suites}

    def _suite(self, snapshot: Path, image_id: str, pattern: str) -> dict:
        name = 'vantage-' + uuid.uuid4().hex
        command = ['docker', 'run', '--rm', '--pull', 'never', '--name', name,
                   '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                   '--security-opt', 'no-new-privileges', '--user', '10001:10001',
                   '--memory', '512m', '--memory-swap', '512m', '--cpus', '1', '--pids-limit', '64',
                   '--ulimit', 'fsize=1048576:1048576', '--log-driver', 'none',
                   '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
                   '--mount', f'type=bind,src={snapshot.resolve()},dst=/workspace,readonly',
                   '--workdir', '/workspace', '--env', 'PYTHONDONTWRITEBYTECODE=1',
                   image_id, 'python', '-m', 'unittest', 'discover', '-s', 'tests', '-p', pattern, '-v']
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            captured = bytearray()
            def drain():
                assert process.stdout is not None
                while True:
                    chunk = process.stdout.read(4096)
                    if not chunk:
                        break
                    remaining = max(0, 65536 - len(captured))
                    captured.extend(chunk[:remaining])
            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            try:
                code = process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                try:
                    subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=15)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                finally:
                    process.kill()
                    process.wait()
                reader.join(timeout=2)
                return {'status': 'timeout', 'tests': 0}
            reader.join(timeout=2)
            output = captured.decode('utf-8', errors='replace')
            counts = re.findall(r'Ran (\d+) tests? in', output)
            count = int(counts[-1]) if counts else 0
            if code in (125, 126, 127) or not counts:
                status = 'error'
            elif count == 0:
                status = 'no_tests'
            else:
                status = 'passed' if code == 0 else 'failed'
            return {'status': status, 'tests': count, 'exit_code': code, 'log': output}
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {'status': 'error', 'tests': 0, 'reason': str(exc)}
        finally:
            try:
                subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                pass
