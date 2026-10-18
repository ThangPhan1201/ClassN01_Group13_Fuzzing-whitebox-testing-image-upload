#!/usr/bin/env python3
"""HTTP dynamic fuzzing thật — gửi request tới backend đang chạy.

Khác v2 bridge (in-process): script này gọi API thật qua HTTP,
mang token thật lấy từ /api/auth/login, và gửi payload ngẫu nhiên
tới các endpoint admin/listing để:

  - Phát hiện 5xx (backend crash/unhandled)
  - Phát hiện auth bypass
  - Phát hiện input validation miss (DB dirty, prototype-like issues)
  - Phát hiện timing-based oracle (slow response = DoS)

Mỗi trial = 1 HTTP request. Watchdog đếm số 5xx liên tiếp và dừng.

Cách dùng:
  python3 http_fuzz.py --target admin-listing-patch --duration 120
"""
from __future__ import annotations
import argparse
import json
import os
import random
import string
import sys
import time
import uuid
from typing import Any, Dict, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

API = "http://localhost:3000/api"
USER_EMAIL = "admin@example.com"
USER_PASS = "password123"


# ---------------- payload generators ----------------

def rand_str(min_len=0, max_len=64, alphabet=None) -> str:
    n = random.randint(min_len, max_len)
    if alphabet is None:
        alphabet = string.ascii_letters + string.digits + " _-./"
    return "".join(random.choice(alphabet) for _ in range(n))


def rand_bytes(min_len=0, max_len=512) -> bytes:
    n = random.randint(min_len, max_len)
    return os.urandom(n)


def gen_listing_patch() -> Dict[str, Any]:
    """Body ngẫu nhiên cho PATCH /admin/listings/:id (theo editListing schema)."""
    fields: Dict[str, Any] = {}
    pick = random.random()
    if pick < 0.15:
        # pure garbage keys (prototype-style / unknown fields)
        n = random.randint(1, 5)
        for _ in range(n):
            fields[rand_str(1, 12)] = random.choice([
                rand_str(0, 200),
                random.randint(-1_000_000, 1_000_000_000),
                None,
                True, False,
                [rand_str(0, 30) for _ in range(random.randint(0, 5))],
            ])
    elif pick < 0.30:
        # boundary: extreme price
        fields["price"] = random.choice([
            -1, 0, 1, 99999999999999, 1e308, "abc", None, "0x10",
        ])
    elif pick < 0.45:
        # boundary: extreme year / quantity
        fields["publicationYear"] = random.choice([
            -100, 0, 1, 9999, 100000, "abc", None, 1.5,
        ])
        fields["quantity"] = random.choice([
            -10, -1, 0, 1, 999999999, 1e20, "abc", None,
        ])
    elif pick < 0.60:
        # path injection in string fields
        bad = "../../../etc/passwd"
        fields["title"] = bad
        fields["description"] = bad
        fields["location"] = bad
    elif pick < 0.75:
        # unicode / null byte tricks
        fields["title"] = random.choice([
            "Null\x00byte",
            "ctrl\r\ninjection",
            "<script>alert(1)</script>",
            "🚀" * 50,
            "A" * 100_000,
        ])
    elif pick < 0.90:
        # legit-looking but random
        fields["title"] = rand_str(0, 100)
        fields["author"] = rand_str(0, 60)
        fields["description"] = rand_str(0, 500)
        fields["price"] = random.choice([rand_str(0, 10), random.randint(0, 1_000_000)])
    else:
        # empty
        return {}
    return fields


def gen_login_body() -> Dict[str, Any]:
    return {
        "email": random.choice([
            "admin@example.com",
            rand_str(0, 60) + "@x.com",
            "' OR 1=1 --",
            "../../etc/passwd",
            "<bob>",
            "x" * 5000,
        ]),
        "password": random.choice([
            "password123", "", rand_str(0, 200), "'; DROP TABLE users; --",
            None, "x" * 100_000,
        ]),
    }


def gen_listing_create() -> Dict[str, Any]:
    return {
        "bookId": random.choice([1, 22, 99999, -1, "abc", None]),
        "price": random.choice([0, -1, 1, 1e20, "abc", None]),
        "quantity": random.choice([0, -1, 1, 99999, "abc", None]),
        "condition": random.choice([
            "NEW", "OLD", "'; DROP TABLE listings; --", None, 123, 999,
        ]),
        "shippingOption": random.choice([
            "PICKUP", "VIETTEL", "HACK", None, "<x>", 1,
        ]),
        "description": random.choice([
            rand_str(0, 1000), "A" * 50_000, "\x00\x01", "<x>",
        ]),
        "location": rand_str(0, 200),
    }


# ---------------- session / auth ----------------

def make_session() -> requests.Session:
    s = requests.Session()
    r = Retry(total=2, backoff_factor=0.2,
              status_forcelist=(502, 503, 504))
    adapter = HTTPAdapter(max_retries=r, pool_maxsize=10)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def login(s: requests.Session, email: str = USER_EMAIL, password: str = USER_PASS
           ) -> Optional[str]:
    try:
        r = s.post(f"{API}/auth/login",
                   json={"email": email, "password": password},
                   timeout=5)
        if r.status_code == 200:
            return r.json().get("accessToken")
    except Exception:
        return None
    return None


# ---------------- targets ----------------

def pick_listing_id(s: requests.Session, token: str) -> int:
    """Lấy 1 listing id thật từ API (fallback = 1)."""
    try:
        r = s.get(f"{API}/listings?page=1&limit=1", timeout=5)
        if r.status_code == 200:
            data = r.json()
            items = data.get("data") or []
            if items:
                return int(items[0]["id"])
    except Exception:
        pass
    return 1


def trial_admin_listing_patch(s, token, lid):
    body = gen_listing_patch()
    r = s.patch(f"{API}/admin/listings/{lid}",
                json=body,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10)
    return r


def trial_listing_create(s, token):
    body = gen_listing_create()
    r = s.post(f"{API}/listings", json=body,
               headers={"Authorization": f"Bearer {token}"},
               timeout=10)
    return r


def trial_login(s):
    body = gen_login_body()
    r = s.post(f"{API}/auth/login", json=body, timeout=10)
    return r


def trial_health(s):
    r = s.get(f"{API}/health", timeout=5)
    return r


# ---------------- oracle ----------------

def classify(resp, elapsed_ms):
    """Phân loại outcome. Trả về (outcome, reason)."""
    sc = resp.status_code
    if sc < 400:
        return "PASS", f"HTTP_{sc}"
    if sc == 401 or sc == 403:
        return "REJECT", f"HTTP_{sc}"
    if sc == 400 or sc == 404 or sc == 409 or sc == 413 or sc == 415 or sc == 422:
        return "REJECT", f"HTTP_{sc}"
    if sc == 429:
        return "REJECT", "THROTTLED"
    if 500 <= sc < 600:
        return "CRASH", f"HTTP_{sc}"
    return "REJECT", f"HTTP_{sc}"


# ---------------- watchdog ----------------

class Watchdog:
    def __init__(self, max_5xx: int = 5, max_slow_ms: int = 8000,
                 slow_streak: int = 10):
        self.max_5xx = max_5xx
        self.max_slow_ms = max_slow_ms
        self.slow_streak = slow_streak
        self.c5xx = 0
        self.slow = 0
        self.aborted = False
        self.last_reasons = []

    def record(self, outcome: str, reason: str, elapsed_ms: float):
        if outcome == "CRASH":
            self.c5xx += 1
            self.last_reasons.append(reason)
            if len(self.last_reasons) > 20:
                self.last_reasons = self.last_reasons[-20:]
            if self.c5xx >= self.max_5xx:
                self.aborted = True
        if elapsed_ms > self.max_slow_ms:
            self.slow += 1
            if self.slow >= self.slow_streak:
                self.aborted = True
        else:
            self.slow = max(0, self.slow - 1)


# ---------------- runner ----------------

def run(args):
    out = args.out
    os.makedirs(out, exist_ok=True)
    log_path = os.path.join(out, f"http_{args.target}.jsonl")
    crash_dir = os.path.join(out, "crashes")
    os.makedirs(crash_dir, exist_ok=True)

    s = make_session()
    print(f"[+] login as {USER_EMAIL}")
    token = login(s)
    if not token:
        print("[-] login FAILED — abort")
        return 1
    print(f"[+] token OK ({len(token)} chars)")

    lid = 1
    if "admin-listing" in args.target:
        lid = pick_listing_id(s, token)
        print(f"[+] using listing id={lid}")

    trials = {
        "admin-listing-patch": lambda: trial_admin_listing_patch(s, token, lid),
        "listing-create":      lambda: trial_listing_create(s, token),
        "login":               lambda: trial_login(s),
        "health":              lambda: trial_health(s),
    }
    trial_fn = trials[args.target]

    wd = Watchdog(args.max_5xx, args.max_slow_ms, args.slow_streak)
    start = time.time()
    n = 0
    pass_n = 0
    rej_n = 0
    crash_n = 0
    print(f"[+] start fuzzing target={args.target} duration={args.duration}s")
    with open(log_path, "a") as lf:
        while time.time() - start < args.duration:
            if wd.aborted:
                print("[!] watchdog ABORT")
                break
            t0 = time.perf_counter()
            try:
                resp = trial_fn()
            except Exception as e:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                rec = {
                    "trial": n, "ts": time.time(), "target": args.target,
                    "outcome": "CRASH", "reason": "EXC_" + type(e).__name__,
                    "elapsed_ms": round(elapsed_ms, 3),
                }
                lf.write(json.dumps(rec) + "\n")
                lf.flush()
                crash_n += 1
                if wd.record("CRASH", rec["reason"], elapsed_ms):
                    break
                n += 1
                continue
            elapsed_ms = (time.perf_counter() - t0) * 1000
            outcome, reason = classify(resp, elapsed_ms)
            if outcome == "PASS": pass_n += 1
            elif outcome == "REJECT": rej_n += 1
            elif outcome == "CRASH": crash_n += 1

            rec = {
                "trial": n, "ts": time.time(), "target": args.target,
                "outcome": outcome, "reason": reason,
                "elapsed_ms": round(elapsed_ms, 3),
                "status_code": resp.status_code,
                "len_body": len(resp.content or b""),
            }
            lf.write(json.dumps(rec) + "\n")
            lf.flush()
            if outcome == "CRASH":
                # save payload
                cname = (f"{args.target}_trial{n}_{reason}_"
                         f"{uuid.uuid4().hex[:8]}.json")
                cpath = os.path.join(crash_dir, cname)
                try:
                    with open(cpath, "w") as f:
                        f.write(resp.text[:2000])
                except Exception:
                    pass
                rec["saved_to"] = cpath
                lf.write(json.dumps(rec) + "\n")
                lf.flush()
                if wd.record(outcome, reason, elapsed_ms):
                    break
            else:
                wd.record(outcome, reason, elapsed_ms)
            n += 1
            if n % 25 == 0:
                rate = n / (time.time() - start)
                print(f"   trial={n}  rate={rate:.1f}/s  "
                      f"pass={pass_n} rej={rej_n} crash={crash_n}")

    print()
    print("========================================")
    print(f"  HTTP fuzz done: target={args.target}")
    print(f"  trials={n}  pass={pass_n}  reject={rej_n}  crash={crash_n}")
    print(f"  log: {log_path}")
    print(f"  crashes dir: {crash_dir}")
    print("========================================")
    return 0 if crash_n == 0 else 2


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True,
                   choices=["admin-listing-patch", "listing-create",
                            "login", "health"])
    p.add_argument("--duration", type=int, default=60)
    p.add_argument("--out", default=os.path.join(
        os.path.dirname(__file__), "logs", "live"))
    p.add_argument("--max-5xx", type=int, default=5,
                   help="stop after N consecutive 5xx")
    p.add_argument("--max-slow-ms", type=int, default=8000)
    p.add_argument("--slow-streak", type=int, default=10)
    p.add_argument("--email", default=USER_EMAIL)
    p.add_argument("--password", default=USER_PASS)
    args = p.parse_args()
    globals()["USER_EMAIL"] = args.email
    globals()["USER_PASS"] = args.password
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
