"""Dynamic runner: mỗi trial spawn 1 process Node mới qua subprocess.
Crash thật của Node (segfault, OOM, hang) sẽ được phát hiện qua returncode/timeout.

Khi crash xảy ra, watchdog sẽ tự giới hạn số lần restart và dừng hẳn nếu vượt ngưỡng.
"""
import json
import os
import subprocess
import time
from core.strategies import gen_random_payload
from core.reporter import build_record


# Map returncode thường gặp
SIGNAL_NAMES = {
    -6:  'SIGABRT',
    -9:  'SIGKILL',
    -11: 'SIGSEGV',
    -15: 'SIGTERM',
}


def _classify_returncode(rc):
    if rc is None:
        return 'CRASH', 'NO_RETURNCODE'
    if rc == 0:
        return None  # success - để caller tự xử lý
    if rc < 0:
        name = SIGNAL_NAMES.get(rc, 'SIGNAL_%d' % rc)
        return 'CRASH', name
    if rc == 2:
        # load error thường do chưa compile
        return 'CRASH', 'LOAD_ERROR'
    return 'CRASH', 'EXIT_%d' % rc


class DynamicRunner:
    def __init__(self, bridge_script, cwd=None, watchdog=None):
        self.bridge_script = bridge_script
        self.cwd = cwd
        self.watchdog = watchdog
        self.trial = 0
        self.running = True

    def _spawn(self, env):
        return subprocess.Popen(
            ['node', self.bridge_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=self.cwd,
            start_new_session=True,
        )

    def _one_trial(self, payload, hang_timeout=10):
        kind, body, mime, name = payload
        env = os.environ.copy()
        env.pop('NODE_OPTIONS', None)
        env['FUZZ_MIME'] = mime
        env['FUZZ_NAME'] = name
        proc = self._spawn(env)
        t0 = time.perf_counter()
        try:
            stdout, stderr = proc.communicate(input=body, timeout=hang_timeout)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            rc = proc.returncode
            cls = _classify_returncode(rc)
            if cls is not None:
                outcome, reason = cls
                return {
                    'outcome': outcome,
                    'reason': reason,
                    'elapsed_ms': round(elapsed_ms, 3),
                    'returncode': rc,
                    'stderr': stderr.decode('utf-8', 'replace')[:500],
                }
            try:
                parsed = json.loads(stdout.decode('utf-8', 'replace'))
            except Exception as e:
                return {
                    'outcome': 'CRASH',
                    'reason': 'BAD_JSON: ' + str(e),
                    'elapsed_ms': round(elapsed_ms, 3),
                    'raw': stdout[:200].decode('utf-8', 'replace'),
                }
            parsed['elapsed_ms'] = round(elapsed_ms, 3)
            return parsed
        except subprocess.TimeoutExpired:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            # kill cả process group
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except Exception:
                proc.kill()
            try:
                proc.wait(timeout=2)
            except Exception:
                pass
            return {
                'outcome': 'CRASH',
                'reason': 'HANG_%ds' % hang_timeout,
                'elapsed_ms': round(elapsed_ms, 3),
                'returncode': None,
            }

    def run(self, duration_s=60, log_path=None, on_crash=None, max_trials=None,
            hang_timeout=10):
        if log_path:
            log_f = open(log_path, 'a')
        else:
            log_f = None
        start = time.time()
        n = 0
        try:
            while self.running and time.time() - start < duration_s:
                if max_trials is not None and n >= max_trials:
                    break
                # Watchdog gate: nếu đã abort thì dừng
                if self.watchdog and self.watchdog.should_abort():
                    print('[dynamic] watchdog requested ABORT')
                    break
                payload = gen_random_payload()
                kind, body, mime, name = payload
                if '\x00' in name:
                    continue
                result = self._one_trial(payload, hang_timeout=hang_timeout)
                rec = build_record('dynamic', self.trial, payload, result)
                if log_f:
                    log_f.write(json.dumps(rec) + '\n')
                    log_f.flush()
                if rec['outcome'] == 'CRASH':
                    if self.watchdog:
                        self.watchdog.record_crash(rec['reason'])
                    if on_crash:
                        on_crash(rec, payload, result)
                    if self.watchdog and self.watchdog.should_abort():
                        print('[dynamic] crash limit reached, aborting')
                        break
                self.trial += 1
                n += 1
        finally:
            if log_f:
                log_f.close()
        return n
