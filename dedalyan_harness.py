"""Общая инфраструктура для тестов и криптоанализа Dedalyan.

Здесь собрано то, что нужно каждому скрипту: разбор аргументов, бюджет
времени с автоподбором числа выборок, параллельный запуск по ядрам,
статистические пороги и единый формат отчёта.

Вывод намеренно на английском: кириллица ломается в консоли Windows (cp866).
Комментарии -- на русском.

Профили бюджета (секунд на скрипт)::

    quick      15     дымовая проверка, годится для CI
    standard  120     значение по умолчанию
    deep     1800     полчаса
    overnight 28800   восемь часов

Число выборок можно задать и напрямую через --samples, тогда бюджет
игнорируется.
"""

from __future__ import annotations

import argparse
import math
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PROFILES = {
    "quick": 15.0,
    "standard": 120.0,
    "deep": 1800.0,
    "overnight": 28800.0,
}

BLOCK_BITS = 96
KEY_BITS = 256
SUBKEY_BITS = 48


# --------------------------------------------------------------------------
# Аргументы командной строки
# --------------------------------------------------------------------------

def make_parser(description: str) -> argparse.ArgumentParser:
    """Парсер с общим набором флагов."""
    p = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--profile", choices=sorted(PROFILES),
                   default=os.environ.get("DEDALYAN_PROFILE", "standard"),
                   help="time budget preset")
    p.add_argument("--budget", type=float, default=None,
                   help="explicit time budget in seconds (overrides --profile)")
    p.add_argument("--samples", type=int, default=None,
                   help="explicit sample count (overrides the time budget)")
    p.add_argument("--rounds", type=int, default=None,
                   help="round count for round-reduced analysis (default: "
                        "script-specific)")
    p.add_argument("--jobs", type=int,
                   default=int(os.environ.get("DEDALYAN_JOBS", "0")) or None,
                   help="worker processes (default: all cores)")
    p.add_argument("--seed", type=int, default=0xD1CE_5EED,
                   help="master seed; the same seed reproduces the same run")
    p.add_argument("--python", action="store_true",
                   help="force the pure-Python backend (very slow)")
    p.add_argument("--verbose", "-v", action="store_true")
    return p


def budget_of(args) -> float:
    if args.budget is not None:
        return max(1.0, args.budget)
    return PROFILES[args.profile]


def jobs_of(args) -> int:
    if args.jobs:
        return max(1, args.jobs)
    return max(1, os.cpu_count() or 1)


# --------------------------------------------------------------------------
# Бэкенд
# --------------------------------------------------------------------------

def get_backend(args=None):
    """Возвращает C-бэкенд или падает с понятным сообщением."""
    from dedalyan_c import backend
    if args is not None and getattr(args, "python", False):
        return None
    if not backend.available:
        raise SystemExit(
            "ERROR: C backend unavailable -- " + (backend.error or "?") +
            "\n       Heavy analysis needs it. Build with:\n"
            "         powershell -ExecutionPolicy Bypass -File build.ps1")
    return backend


def random_key(rng) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(32))


# --------------------------------------------------------------------------
# Автоподбор числа выборок под бюджет
# --------------------------------------------------------------------------

def autoscale(probe: Callable[[int], None], budget: float,
              probe_n: int = 20_000, min_n: int = 1_000,
              max_n: int = 1 << 40, verbose: bool = False) -> int:
    """Подбирает число выборок, укладывающееся в бюджет.

    ``probe(n)`` должна выполнить ровно ту работу, что и основной проход,
    но на n выборках. Замер повторяется, пока не наберётся хотя бы 30 мс,
    иначе оценка скорости слишком шумная.
    """
    n = probe_n
    while True:
        t0 = time.perf_counter()
        probe(n)
        dt = time.perf_counter() - t0
        if dt >= 0.03 or n >= (1 << 26):
            break
        n *= 8
    rate = n / max(dt, 1e-9)
    target = int(rate * budget)
    target = max(min_n, min(max_n, target))
    if verbose:
        print(f"  [autoscale] {rate:,.0f} samples/s -> {target:,} samples "
              f"for {budget:.0f}s")
    return target


def split_work(total: int, jobs: int, min_chunk: int = 1) -> List[int]:
    """Делит total на jobs частей (последняя добирает остаток)."""
    if jobs <= 1 or total <= min_chunk:
        return [total]
    base = max(min_chunk, total // jobs)
    chunks = [base] * jobs
    rem = total - base * jobs
    i = 0
    while rem > 0:
        chunks[i % jobs] += 1
        rem -= 1
        i += 1
    return [c for c in chunks if c > 0]


_POOL: Optional[ProcessPoolExecutor] = None
_POOL_JOBS = 0


def _get_pool(jobs: int) -> ProcessPoolExecutor:
    """Постоянный пул процессов.

    На Windows используется spawn: каждый воркер заново запускает интерпретатор
    и импортирует numpy с ctypes, что стоит примерно полсекунды. Скрипты вроде
    boomerang вызывают parallel_map сотни раз в цикле, поэтому создавать пул на
    каждый вызов недопустимо -- накладные расходы съедают весь бюджет.
    """
    global _POOL, _POOL_JOBS
    if _POOL is None or _POOL_JOBS != jobs:
        if _POOL is not None:
            _POOL.shutdown(wait=False)
        _POOL = ProcessPoolExecutor(max_workers=jobs)
        _POOL_JOBS = jobs
    return _POOL


def shutdown_pool() -> None:
    global _POOL, _POOL_JOBS
    if _POOL is not None:
        _POOL.shutdown(wait=False)
        _POOL = None
        _POOL_JOBS = 0


import atexit as _atexit
_atexit.register(shutdown_pool)


def parallel_map(worker: Callable, tasks: Sequence, jobs: int,
                 verbose: bool = False):
    """Запускает worker(task) по процессам. При jobs == 1 -- в текущем.

    worker обязан быть функцией верхнего уровня модуля: на Windows
    используется spawn, и замыкания не сериализуются.
    """
    if jobs <= 1 or len(tasks) <= 1:
        return [worker(t) for t in tasks]
    return list(_get_pool(jobs).map(worker, tasks))


# --------------------------------------------------------------------------
# Статистика
# --------------------------------------------------------------------------

def binom_sigma(n: int, p: float = 0.5) -> float:
    """Стандартное отклонение доли для биномиального распределения."""
    return math.sqrt(p * (1.0 - p) / max(n, 1))


def z_score(observed: float, n: int, p: float = 0.5) -> float:
    """Отклонение наблюдённой доли от p в сигмах."""
    s = binom_sigma(n, p)
    return (observed - p) / s if s > 0 else 0.0


def noise_threshold(n: int, tests: int = 1, p: float = 0.5,
                    alpha: float = 0.01) -> float:
    """Порог смещения, за которым результат не объясняется шумом.

    Поправка Бонферрони на число одновременных проверок: при 10^6 тестов
    трёх сигм заведомо мало, ложные срабатывания посыплются пачками.
    """
    from statistics import NormalDist
    tests = max(1, tests)
    z = NormalDist().inv_cdf(1.0 - alpha / (2.0 * tests))
    return z * binom_sigma(n, p)


def chi2_sf(x: float, df: int) -> float:
    """Правый хвост распределения хи-квадрат (через scipy, иначе -- оценка)."""
    try:
        from scipy.stats import chi2
        return float(chi2.sf(x, df))
    except ImportError:
        # Приближение Уилсона--Хилферти: достаточно при df >= 30.
        t = (x / df) ** (1.0 / 3.0)
        m = 1.0 - 2.0 / (9.0 * df)
        s = math.sqrt(2.0 / (9.0 * df))
        from statistics import NormalDist
        return 1.0 - NormalDist().cdf((t - m) / s)


def erfc(x: float) -> float:
    return math.erfc(x)


# --------------------------------------------------------------------------
# Отчёт
# --------------------------------------------------------------------------

class Reporter:
    """Единый формат вывода: заголовки, строки, проверки, итог."""

    def __init__(self, title: str, quiet: bool = False) -> None:
        self.title = title
        self.quiet = quiet
        self.passed = 0
        self.failed = 0
        self.warned = 0
        self.notes: List[str] = []
        self.t0 = time.perf_counter()
        width = max(60, len(title) + 4)
        print("=" * width)
        print(title)
        print("=" * width)

    def section(self, name: str) -> None:
        print()
        print(f"-- {name} " + "-" * max(2, 58 - len(name)))

    def info(self, msg: str) -> None:
        print(f"   {msg}")

    def row(self, *cols) -> None:
        print("   " + "  ".join(str(c) for c in cols))

    def check(self, cond: bool, name: str, detail: str = "") -> bool:
        if cond:
            self.passed += 1
            print(f"   [PASS] {name}" + (f"   {detail}" if detail else ""))
        else:
            self.failed += 1
            print(f"   [FAIL] {name}" + (f"   {detail}" if detail else ""))
            self.notes.append(f"FAIL: {name} {detail}".rstrip())
        return cond

    def warn(self, name: str, detail: str = "") -> None:
        self.warned += 1
        print(f"   [WARN] {name}" + (f"   {detail}" if detail else ""))
        self.notes.append(f"WARN: {name} {detail}".rstrip())

    def note(self, name: str, detail: str = "") -> None:
        """Наблюдение без вердикта: для величин, которые нечему сравнивать."""
        print(f"   [NOTE] {name}" + (f"   {detail}" if detail else ""))

    def summary(self) -> int:
        dt = time.perf_counter() - self.t0
        print()
        print("=" * 60)
        print(f"{self.passed} passed, {self.failed} failed, "
              f"{self.warned} warnings   ({dt:.1f}s)")
        if self.notes:
            print()
            for n in self.notes:
                print("  " + n)
        print("=" * 60)
        return 1 if self.failed else 0


def fmt_bits(x: int, width: int = 12) -> str:
    return f"{x:0{width}x}"


def fmt_pct(x: float) -> str:
    return f"{100.0 * x:6.2f}%"
