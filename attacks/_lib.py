"""Общее для криптоаналитических скриптов Dedalyan.

Здесь -- то, что повторяется в каждой атаке: генерация кандидатов (разностей,
масок), расчёт порога значимости с поправкой на множественные сравнения,
таблица «раунд -> найденное отклонение» и вывод вердикта о запасе прочности.

Ключевая идея порогов. Если проверяется T гипотез сразу, то при пороге в
k сигм ложные срабатывания появятся, как только T превысит примерно 1/p(k).
Поэтому всюду используется поправка Бонферрони: порог берётся по alpha/T,
а не по alpha. Без неё скрипт на 10^6 проверок «находит» атаку на любом,
даже идеальном шифре.
"""

from __future__ import annotations

import math
import random
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dedalyan_harness import (Reporter, autoscale, binom_sigma, get_backend,
                             jobs_of, make_parser, noise_threshold,
                             parallel_map, split_work)          # noqa: F401

W = 48
MASK = (1 << W) - 1
BLOCK_BITS = 96
ROUNDS = 16

# Во сколько раз бюджет отличается от «стандартного» профиля.
PROFILE_SCALE = {"quick": 0.12, "standard": 1.0, "deep": 15.0,
                 "overnight": 240.0}


def profile_scale(args) -> float:
    if args.samples:
        return args.samples / 1_000_000
    if args.budget is not None:
        return args.budget / 120.0
    return PROFILE_SCALE[args.profile]


# --------------------------------------------------------------------------
# Кандидаты
# --------------------------------------------------------------------------

def single_bit_differences() -> List[Tuple[int, int]]:
    """96 однобитовых разностей блока как пары (dl, dr)."""
    out = []
    for b in range(BLOCK_BITS):
        out.append((1 << (b - 48), 0) if b >= 48 else (0, 1 << b))
    return out


def low_weight_differences(max_weight: int = 3,
                           limit: Optional[int] = None,
                           rng: Optional[random.Random] = None
                           ) -> List[Tuple[int, int]]:
    """Разности малого веса Хэмминга: у ARX-шифров именно они дают
    характеристики с наибольшей вероятностью."""
    out: List[Tuple[int, int]] = []
    bits = list(range(BLOCK_BITS))
    from itertools import combinations
    for w in range(1, max_weight + 1):
        for combo in combinations(bits, w):
            dl = dr = 0
            for b in combo:
                if b >= 48:
                    dl |= 1 << (b - 48)
                else:
                    dr |= 1 << b
            out.append((dl, dr))
            if limit and len(out) >= limit:
                return out
    if rng is not None:
        rng.shuffle(out)
    return out


def random_differences(n: int, rng: random.Random) -> List[Tuple[int, int]]:
    return [(rng.getrandbits(48), rng.getrandbits(48)) for _ in range(n)]


def single_bit_masks() -> List[Tuple[int, int]]:
    return single_bit_differences()


def random_masks(n: int, rng: random.Random,
                 weight: Optional[int] = None) -> List[Tuple[int, int]]:
    """Случайные маски. weight=None -- плотные, иначе заданный вес."""
    out = []
    for _ in range(n):
        if weight is None:
            out.append((rng.getrandbits(48), rng.getrandbits(48)))
        else:
            bits = rng.sample(range(BLOCK_BITS), weight)
            ml = mr = 0
            for b in bits:
                if b >= 48:
                    ml |= 1 << (b - 48)
                else:
                    mr |= 1 << b
            out.append((ml, mr))
    return out


def pack96(l: int, r: int) -> int:
    return ((l & MASK) << 48) | (r & MASK)


def unpack96(x: int) -> Tuple[int, int]:
    return (x >> 48) & MASK, x & MASK


def hw96(l: int, r: int) -> int:
    return bin(l & MASK).count("1") + bin(r & MASK).count("1")


def fmt_diff(l: int, r: int) -> str:
    return f"{l & MASK:012x}:{r & MASK:012x}"


# --------------------------------------------------------------------------
# Вердикты
# --------------------------------------------------------------------------

class RoundVerdict:
    """Накапливает «на каком раунде свойство ещё наблюдается»."""

    def __init__(self, name: str, total_rounds: int = ROUNDS) -> None:
        self.name = name
        self.total_rounds = total_rounds
        self.rows: List[Tuple[int, float, float, str, bool]] = []

    def add(self, rounds: int, best: float, threshold: float,
            witness: str = "") -> bool:
        detected = best > threshold
        self.rows.append((rounds, best, threshold, witness, detected))
        return detected

    @property
    def last_detected(self) -> Optional[int]:
        det = [r for r, _, _, _, d in self.rows if d]
        return max(det) if det else None

    def report(self, r: Reporter) -> None:
        r.section(f"Verdict -- {self.name}")
        r.row(f"{'rounds':>7}  {'best deviation':>15}  {'noise floor':>12}  "
              f"{'detected':>8}  witness")
        for rounds, best, thr, wit, det in self.rows:
            r.row(f"{rounds:>7}  {best:15.6f}  {thr:12.6f}  "
                  f"{'YES' if det else 'no':>8}  {wit}")
        last = self.last_detected
        if last is None:
            r.note(f"{self.name}: nothing above the noise floor at any tested "
                   f"round count")
        else:
            margin = self.total_rounds - last
            r.note(f"{self.name}: last detected at round {last}; "
                   f"margin {margin} of {self.total_rounds} rounds")
            if margin < 4:
                r.warn(f"{self.name}: margin is only {margin} rounds",
                       "a full cipher needs a wider gap to be comfortable")


def secure_round_summary(r: Reporter, verdicts: Sequence[RoundVerdict],
                         total_rounds: int = ROUNDS) -> None:
    r.section("Security margin")
    worst = 0
    for v in verdicts:
        last = v.last_detected
        if last is not None:
            worst = max(worst, last)
        r.row(f"{v.name:<34} last detected round: "
              f"{last if last is not None else '-'}")
    if worst:
        r.note(f"deepest distinguisher found: round {worst} of {total_rounds}"
               f"   margin {total_rounds - worst} rounds "
               f"({100.0 * (total_rounds - worst) / total_rounds:.0f}%)")
    else:
        r.note("no distinguisher found at any tested round count")
    r.info("Reminder: absence of a distinguisher here is NOT a security proof.")
    r.info("These are bounded searches, not exhaustive cryptanalysis.")
