"""Запуск всего криптоаналитического набора.

Профили времени (примерно, на 12 ядрах)::

    quick      ~5 минут    дымовая проверка
    standard   ~40 минут   значение по умолчанию
    deep       ~8 часов
    overnight  сутки и больше

Каждый скрипт запускается отдельным процессом, поэтому падение одного не
останавливает остальные. Логи пишутся в attacks/reports/.

Запуск:  python attacks/run_all.py
         python attacks/run_all.py --profile deep
         python attacks/run_all.py --only differential,linear
"""

from __future__ import annotations

import argparse
import datetime
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

ATTACKS = [
    ("structural", "structural.py", []),
    ("differential", "differential.py", []),
    ("linear", "linear.py", []),
    ("integral", "integral.py", []),
    ("boomerang", "boomerang.py", []),
    ("impossible", "impossible.py", []),
    ("related_key", "related_key.py", []),
    ("key_schedule", "key_schedule.py", []),
    ("randomness", "randomness.py", []),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--profile", default="standard",
                    choices=["quick", "standard", "deep", "overnight"])
    ap.add_argument("--only", default=None,
                    help="comma-separated subset")
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--reports", default=None,
                    help="directory for logs (default attacks/reports)")
    args = ap.parse_args()

    selected = ATTACKS
    if args.only:
        want = {s.strip() for s in args.only.split(",")}
        unknown = want - {n for n, _, _ in ATTACKS}
        if unknown:
            print(f"unknown names: {sorted(unknown)}")
            print(f"available: {[n for n, _, _ in ATTACKS]}")
            return 2
        selected = [a for a in ATTACKS if a[0] in want]

    sys.path.insert(0, str(ROOT))
    from dedalyan_c import backend
    if not backend.available:
        print("ERROR: C backend not built. The attack suite needs it.")
        print("  powershell -ExecutionPolicy Bypass -File build.ps1")
        return 2

    reports = Path(args.reports) if args.reports else HERE / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    print("=" * 62)
    print(f"Dedalyan cryptanalysis suite -- profile '{args.profile}'")
    print(f"reports: {reports}")
    print("=" * 62)
    print()
    print("REMINDER: this suite runs bounded searches. Finding nothing is")
    print("evidence of no CHEAP break, not a proof of security.")
    print()

    results = []
    t_start = time.perf_counter()
    for name, script, extra in selected:
        cmd = [sys.executable, str(HERE / script), "--profile", args.profile]
        cmd += extra
        if args.jobs:
            cmd += ["--jobs", str(args.jobs)]
        if args.seed is not None:
            cmd += ["--seed", str(args.seed)]

        log = reports / f"{stamp}-{name}.log"
        print(f"[{time.strftime('%H:%M:%S')}] running {name} -> {log.name}")
        t0 = time.perf_counter()
        with open(log, "w", encoding="utf-8") as fh:
            proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    encoding="utf-8", errors="replace")
            for line in proc.stdout:
                fh.write(line)
            rc = proc.wait()
        dt = time.perf_counter() - t0
        results.append((name, rc, dt, log))
        print(f"           {'ok' if rc == 0 else 'FAILED'}  ({dt:.1f}s)")

    print()
    print("=" * 62)
    print("SUMMARY")
    print("=" * 62)
    for name, rc, dt, log in results:
        print(f"  {'ok    ' if rc == 0 else 'FAILED'}  {name:<14} "
              f"{dt:8.1f}s   {log.name}")
    bad = [n for n, rc, _, _ in results if rc != 0]
    print()
    print(f"  {len(results) - len(bad)}/{len(results)} completed in "
          f"{time.perf_counter() - t_start:.1f}s")
    if bad:
        print(f"  non-zero exit: {', '.join(bad)}")

    # Собираем строки с вердиктами из логов -- их удобно читать одним куском.
    print()
    print("=" * 62)
    print("KEY FINDINGS (lines marked NOTE / WARN / FAIL)")
    print("=" * 62)
    for name, _, _, log in results:
        lines = [l.rstrip() for l in log.read_text(encoding="utf-8",
                                                   errors="replace").splitlines()
                 if "[NOTE]" in l or "[WARN]" in l or "[FAIL]" in l]
        if lines:
            print(f"\n-- {name} " + "-" * max(2, 50 - len(name)))
            for l in lines:
                print("  " + l.strip())

    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
