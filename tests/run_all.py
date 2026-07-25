"""Запуск всего тестового набора одной командой.

Каждый тест выполняется отдельным процессом: падение одного не мешает
остальным, а код возврата собирается в общий итог.

Запуск:  python tests/run_all.py
         python tests/run_all.py --profile quick
         python tests/run_all.py --only vectors,pitfalls
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# (имя, файл, обязателен ли C-бэкенд)
TESTS = [
    ("vectors", "test_vectors.py", False),
    ("pitfalls", "test_pitfalls.py", False),
    ("roundtrip", "test_roundtrip.py", True),
    ("cross_c", "test_cross_c.py", True),
    ("avalanche", "test_avalanche.py", True),
    ("diffusion", "test_diffusion.py", True),
    ("schedule", "test_schedule.py", True),
    ("statistics", "test_statistics.py", True),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--profile", default="standard",
                    choices=["quick", "standard", "deep", "overnight"])
    ap.add_argument("--only", default=None,
                    help="comma-separated subset of test names")
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    selected = TESTS
    if args.only:
        want = {s.strip() for s in args.only.split(",")}
        unknown = want - {n for n, _, _ in TESTS}
        if unknown:
            print(f"unknown test names: {sorted(unknown)}")
            print(f"available: {[n for n, _, _ in TESTS]}")
            return 2
        selected = [t for t in TESTS if t[0] in want]

    # Наличие C-бэкенда проверяем один раз, чтобы не гонять заведомо
    # падающие тесты.
    sys.path.insert(0, str(ROOT))
    from dedalyan_c import backend
    if not backend.available:
        print("WARNING: C backend not built -- heavy tests will be skipped.")
        print("         powershell -ExecutionPolicy Bypass -File build.ps1")
        print()
        selected = [t for t in selected if not t[2]]

    results = []
    t_start = time.perf_counter()
    for name, script, _ in selected:
        cmd = [sys.executable, str(HERE / script), "--profile", args.profile]
        if args.jobs:
            cmd += ["--jobs", str(args.jobs)]
        if args.seed is not None:
            cmd += ["--seed", str(args.seed)]
        print()
        print("#" * 62)
        print(f"# {name}")
        print("#" * 62)
        t0 = time.perf_counter()
        rc = subprocess.call(cmd, cwd=str(ROOT))
        results.append((name, rc, time.perf_counter() - t0))

    print()
    print("#" * 62)
    print("# SUMMARY")
    print("#" * 62)
    for name, rc, dt in results:
        print(f"  {'PASS' if rc == 0 else 'FAIL'}  {name:<12} {dt:7.1f}s")
    failed = [n for n, rc, _ in results if rc != 0]
    print()
    print(f"  {len(results) - len(failed)}/{len(results)} suites passed "
          f"in {time.perf_counter() - t_start:.1f}s")
    if failed:
        print(f"  failed: {', '.join(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
