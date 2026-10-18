#!/usr/bin/env python3
"""Entry point: --mode {static|dynamic|both}.

Ví dụ:
  python3 run_fuzzer.py --mode static --duration 30
  python3 run_fuzzer.py --mode dynamic --duration 60 --watchdog
  python3 run_fuzzer.py --mode both --duration 60 --watchdog
"""
import argparse
import os
import sys
import time
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # add v2/ so 'from core.x' works
sys.path.insert(0, os.path.join(HERE, 'core'))  # for direct core.x import

from core.runner_static import StaticRunner
from core.runner_dynamic import DynamicRunner
from core.watchdog import Watchdog
from core.reporter import save_crash


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--mode', choices=['static', 'dynamic', 'both'],
                   default='both')
    p.add_argument('--duration', type=int, default=60,
                   help='Thời gian chạy (giây)')
    p.add_argument('--out', default=os.path.join(HERE, 'logs', 'live'),
                   help='Thư mục output')
    p.add_argument('--watchdog', action='store_true',
                   help='Bật watchdog + auto-restart có giới hạn (dynamic)')
    p.add_argument('--max-restarts', type=int, default=3)
    p.add_argument('--cooldown-s', type=int, default=30)
    p.add_argument('--window-s', type=int, default=300)
    p.add_argument('--max-trials', type=int, default=None,
                   help='Dừng sau N trial (mỗi mode)')
    p.add_argument('--hang-timeout', type=int, default=10)
    p.add_argument('--bridge', default=os.path.join(HERE, 'bridge',
                                                    'run_validate.js'))
    p.add_argument('--seed', type=int, default=None)
    args = p.parse_args()

    if args.seed is not None:
        import random
        random.seed(args.seed)

    os.makedirs(args.out, exist_ok=True)
    crash_dir = os.path.join(args.out, 'crashes')
    os.makedirs(crash_dir, exist_ok=True)

    static_log = os.path.join(args.out, 'static.jsonl')
    dynamic_log = os.path.join(args.out, 'dynamic.jsonl')

    summary = {
        'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'mode': args.mode,
        'duration_s': args.duration,
        'watchdog': args.watchdog,
        'static': {'trials': 0, 'pass': 0, 'reject': 0, 'crash': 0},
        'dynamic': {'trials': 0, 'pass': 0, 'reject': 0, 'crash': 0},
    }

    def on_crash(rec, payload, result):
        print('\n🔴 [CRASH] trial=%d mode=%s kind=%s reason=%s' % (
            rec['trial'], rec['mode'], rec['kind'], rec['reason']))
        bin_path, meta_path = save_crash(crash_dir, rec, payload, result)
        print('   saved:', bin_path)
        print()

    def make_watchdog():
        if not args.watchdog:
            return None
        wd = Watchdog(
            max_restarts=args.max_restarts,
            cooldown_s=args.cooldown_s,
            window_s=args.window_s,
        )
        return wd

    t_total = time.time()

    if args.mode in ('static', 'both'):
        print('=== STATIC mode ===')
        runner = StaticRunner(bridge_script=args.bridge)
        n = runner.run(duration_s=args.duration, log_path=static_log,
                       on_crash=on_crash, max_trials=args.max_trials)
        # Đếm lại từ log
        summary['static']['trials'] = n
        with open(static_log) as f:
            for line in f:
                rec = json.loads(line)
                summary['static'][rec['outcome'].lower()] = \
                    summary['static'].get(rec['outcome'].lower(), 0) + 1

    if args.mode in ('dynamic', 'both'):
        print('=== DYNAMIC mode ===')
        wd = make_watchdog()
        runner = DynamicRunner(bridge_script=args.bridge, watchdog=wd)
        n = runner.run(duration_s=args.duration, log_path=dynamic_log,
                       on_crash=on_crash, max_trials=args.max_trials,
                       hang_timeout=args.hang_timeout)
        summary['dynamic']['trials'] = n
        with open(dynamic_log) as f:
            for line in f:
                rec = json.loads(line)
                key = rec['outcome'].lower()
                summary['dynamic'][key] = summary['dynamic'].get(key, 0) + 1
        if wd:
            summary['watchdog_stats'] = wd.stats()

    summary['ended_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
    summary['total_elapsed_s'] = round(time.time() - t_total, 2)

    summary_path = os.path.join(args.out, 'summary.txt')
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)

    print('\n=== SUMMARY ===')
    print(json.dumps(summary, indent=2))
    print('\nLog: %s' % summary_path)


if __name__ == '__main__':
    main()
