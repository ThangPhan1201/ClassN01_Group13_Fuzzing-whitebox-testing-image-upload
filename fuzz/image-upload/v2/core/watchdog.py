"""Watchdog: theo dõi crash, tự dừng nếu crash quá nhiều trong cửa sổ thời gian.
Đơn giản hoá cho Cách B: vì mỗi trial = 1 process mới, mỗi crash tự nhiên
"restart" trial tiếp theo (process mới). Watchdog ở đây chỉ đếm và dừng
nếu quá nhiều crash liên tiếp trong thời gian ngắn.
"""
import time
import threading


class Watchdog:
    def __init__(self, max_restarts=3, cooldown_s=30, window_s=300,
                 on_alert=None):
        self.max_restarts = max_restarts
        self.cooldown_s = cooldown_s
        self.window_s = window_s
        self.on_alert = on_alert or (lambda m: print('[WATCHDOG]', m))
        self._lock = threading.Lock()
        self._crash_times = []
        self._aborted = False
        self._cooldown_until = 0
        self._last_crash = None
        self._total_crashes = 0

    def record_crash(self, reason):
        with self._lock:
            now = time.time()
            # Nếu trong cooldown thì bỏ qua, chỉ cập nhật last
            if now < self._cooldown_until:
                self._last_crash = reason
                return
            # Bỏ crash cũ ngoài window
            self._crash_times = [t for t in self._crash_times
                                 if now - t < self.window_s]
            self._crash_times.append(now)
            self._total_crashes += 1
            self._last_crash = reason
            if len(self._crash_times) >= self.max_restarts:
                self._aborted = True
                self.on_alert(
                    'ABORT: %d crashes in %ds (last: %s)' % (
                        len(self._crash_times), self.window_s, reason
                    )
                )
            else:
                # Bật cooldown
                self._cooldown_until = now + self.cooldown_s
                self.on_alert(
                    'crash #%d/%d in window: %s (cooldown %ds)' % (
                        len(self._crash_times), self.max_restarts,
                        reason, self.cooldown_s
                    )
                )

    def should_abort(self):
        with self._lock:
            return self._aborted

    def stats(self):
        with self._lock:
            return {
                'total_crashes': self._total_crashes,
                'crashes_in_window': len(self._crash_times),
                'max_restarts': self.max_restarts,
                'window_s': self.window_s,
                'aborted': self._aborted,
                'last_crash': self._last_crash,
            }
