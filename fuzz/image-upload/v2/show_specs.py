#!/usr/bin/env python3
"""
V2 — Display the full image-upload fuzzing pipeline report in the terminal.

  Phase 3: ERROR SPECIFICATION  (specs.py)
  Phase 4: REQUIREMENT EXTRACTION (logs/reports/req_extraction.json)
  Phase 7: CWE MAPPING (cwe_mapping.json)

Usage:
    python3 show_specs.py           # all three phases
    python3 show_specs.py spec      # only specifications
    python3 show_specs.py req       # only requirements
    python3 show_specs.py cwe       # only CWE mapping
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from specs import SPECS  # noqa: E402

LINE = "=" * 56


def banner(title: str) -> None:
    print(LINE)
    print(f" {title}".center(56))
    print(LINE)


# ----------------------------------------------------------------------
# Phase 3 — Error Specification
# ----------------------------------------------------------------------
def show_spec() -> None:
    banner("IMAGE UPLOAD FUZZING - ERROR SPECIFICATION (V2)")
    for s in SPECS:
        print(f"[IMG-{s['id'][4:]}] {s['title']}")
        print(f"  Input:       {s['input']}")
        print(f"  Expected:    {s['expected']}")
        print(f"  Severity:    {s['severity']}")
        print()
    print(LINE)
    print(f" Total specifications: {len(SPECS)}")
    print(" Status: SPECIFICATIONS LOADED")
    print(LINE)


# ----------------------------------------------------------------------
# Phase 4 — Requirement Extraction
# ----------------------------------------------------------------------
def show_req() -> None:
    req_path = HERE / "logs" / "reports" / "req_extraction.json"
    if not req_path.exists():
        print(f"[!] Missing {req_path} — run module_log_analyzer.py first.")
        return
    reqs = json.loads(req_path.read_text(encoding="utf-8"))

    banner("IMAGE UPLOAD FUZZING - REQUIREMENT EXTRACTION (V2)")
    for r in reqs:
        print(f"[{r['req']}]")
        print(f"  Branch:     {r['branch']}")
        print(f"  Keyword:    {r['src_keyword']}")
        line = r["line"] if r["line"] else "(patch/added)"
        print(f"  Line:       {line}")
        print()
    print(LINE)
    print(f" Total requirements: {len(reqs)}")
    print(" Status: REQUIREMENTS EXTRACTED")
    print(LINE)


# ----------------------------------------------------------------------
# Phase 7 — CWE Mapping
# ----------------------------------------------------------------------
def show_cwe() -> None:
    cwe_path = HERE / "cwe_mapping.json"
    if not cwe_path.exists():
        print(f"[!] Missing {cwe_path}")
        return
    cwe = json.loads(cwe_path.read_text(encoding="utf-8"))

    banner("IMAGE UPLOAD FUZZING - CWE MAPPING (V2)")
    m_keys = sorted(
        (k for k in cwe if k.startswith("M")),
        key=lambda x: int(x[1:]),
    )
    for mid in m_keys:
        m = cwe[mid]
        print(f"[{mid}] {m['name']}")
        print(f"  CWE:        {m['cwe']}")
        print(f"  CVE:        {m['cve_example']}")
        print(f"  REQ:        {m['req']}")
        print(f"  Group:      {m['group']}")
        print(f"  Breaks:     {m['what_breaks']}")
        print()
    print(LINE)
    print(f" Total mutants: {len(m_keys)}")
    print(" Status: CWE MAPPING COMPLETE")
    print(LINE)


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def main(argv: Iterable[str]) -> int:
    args = list(argv)
    if not args or "all" in args:
        show_spec()
        print()
        show_req()
        print()
        show_cwe()
        return 0

    cmd = args[0]
    if cmd == "spec":
        show_spec()
    elif cmd == "req":
        show_req()
    elif cmd == "cwe":
        show_cwe()
    else:
        print(f"Unknown command: {cmd}")
        print("Usage: python3 show_specs.py [spec|req|cwe|all]")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
