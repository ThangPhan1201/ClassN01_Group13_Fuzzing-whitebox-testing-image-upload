"""Static runner: gọi 1 process Node duy nhất, truyền payload qua stdin nhiều lần.
Tốc độ cao (~hundreds trials/s), phát hiện lỗi logic trong validateFile.
"""
import json
import os
import subprocess
import time
from core.strategies import gen_random_payload
from core.reporter import build_record


class StaticRunner:
    def __init__(self, bridge_script, cwd=None):
        self.bridge_script = bridge_script
        self.cwd = cwd
        self.proc = None
        self.trial = 0

    def _start(self):
        env = os.environ.copy()
        # BỎ NODE_OPTIONS để tránh inspector can thiệp
        env.pop('NODE_OPTIONS', None)
        self.proc = subprocess.Popen(
            ['node', self.bridge_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=self.cwd,
        )

    def _stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            try:
                self.proc.wait(timeout=2)
            except Exception:
                pass
        self.proc = None

    def _one_trial(self, payload):
        kind, body, mime, name = payload
        env = {'FUZZ_MIME': mime, 'FUZZ_NAME': name}
        # StaticRunner dùng lại 1 process; truyền env qua 1 lần
        # (vì process.Popen.env chỉ set khi start). Workaround: restart mỗi trial
        # để env đúng — vẫn nhanh hơn dynamic vì 0 warm-up interpreter.
        env_full = os.environ.copy()
        env_full.pop('NODE_OPTIONS', None)
        env_full.update(env)
        proc = subprocess.Popen(
            ['node', self.bridge_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env_full,
            cwd=self.cwd,
        )
        t0 = time.perf_counter()
        try:
            stdout, stderr = proc.communicate(input=body, timeout=10)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            rc = proc.returncode
            if rc != 0:
                return {
                    'outcome': 'CRASH',
                    'reason': 'node exit code %d' % rc,
                    'elapsed_ms': round(elapsed_ms, 3),
                    'stderr': stderr.decode('utf-8', 'replace')[:500],
                }
            try:
                parsed = json.loads(stdout.decode('utf-8', 'replace'))
            except Exception:
                return {
                    'outcome': 'CRASH',
                    'reason': 'bad json output',
                    'elapsed_ms': round(elapsed_ms, 3),
                    'raw': stdout[:200].decode('utf-8', 'replace'),
                }
            parsed['elapsed_ms'] = round(elapsed_ms, 3)
            return parsed
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return {
                'outcome': 'CRASH',
                'reason': 'TIMEOUT',
                'elapsed_ms': 10000.0,
            }

    def run(self, duration_s=60, log_path=None, on_crash=None, max_trials=None):
        if log_path:
            log_f = open(log_path, 'a')
        else:
            log_f = None
        start = time.time()
        n = 0
        try:
            while time.time() - start < duration_s:
                if max_trials is not None and n >= max_trials:
                    break
                payload = gen_random_payload()
                kind, body, mime, name = payload
                # Skip payloads with null byte in name (cannot pass via argv/env)
                if '\x00' in name:
                    continue
                result = self._one_trial(payload)
                rec = build_record('static', self.trial, payload, result)
                if log_f:
                    log_f.write(json.dumps(rec) + '\n')
                    log_f.flush()
                if rec['outcome'] == 'CRASH' and on_crash:
                    on_crash(rec, payload, result)
                self.trial += 1
                n += 1
        finally:
            self._stop()
            if log_f:
                log_f.close()
        return n


# Cho phép chạy trực tiếp để test
if __name__ == '__main__':
    import sys
    HERE = os.path.dirname(os.path.abspath(__file__))
    BRIDGE = os.path.normpath(os.path.join(HERE, '..', 'bridge', 'run_validate.js'))
    runner = StaticRunner(BRIDGE)
    n = runner.run(duration_s=10)
    print('done', n)
