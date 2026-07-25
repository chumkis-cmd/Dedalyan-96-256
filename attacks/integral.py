"""Интегральный криптоанализ и алгебраическая степень Dedalyan.

Идея. Возьмём аффинное подпространство входов размерности k (k активных бит
перебираются по всем 2^k значениям, остальные фиксированы) и сложим все
шифротексты по XOR. Эта сумма -- производная порядка k. Она тождественно
равна нулю, если алгебраическая степень выходного бита как функции от входа
меньше k. Нулевая сумма при малом k -- это интегральный различитель:
свойство, которого у случайной перестановки быть не должно.

Отсюда сразу два результата:

* глубина интегрального различителя -- максимальное число раундов, на котором
  сумма ещё нулевая;
* оценка алгебраической степени -- минимальное k, при котором сумма перестаёт
  быть нулевой.

Перебирается 2^k блоков, поэтому k ограничен бюджетом: k = 24 это 16.7 млн
шифрований (доли секунды), k = 30 -- миллиард (около минуты на ядро).

Запуск:  python attacks/integral.py
         python attacks/integral.py --profile deep --max-k 28
"""

from __future__ import annotations

import math
import random
import sys
from pathlib import Path
from typing import List, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _lib import (MASK, Reporter, RoundVerdict, get_backend, jobs_of,
                  make_parser, parallel_map, profile_scale,
                  secure_round_summary, split_work)


def _w_integral(task):
    """Считает XOR-суммы для набора (базовая точка, активные биты)."""
    key, rounds, jobs_list = task
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    out = []
    for base_l, base_r, active in jobs_list:
        sl, sr = backend.integral_sum(ctx, rounds, base_l, base_r, active)
        out.append((sl, sr))
    return out


def active_sets(k: int, rng: random.Random, count: int,
                mode: str = "l-half") -> List[List[int]]:
    """Наборы активных бит (индексы 0..95, где 48..95 -- половина L).

    l-half   -- насыщается СТАРШАЯ половина. Это канонический интеграл для
                сети Фейстеля: после первого раунда L₁ = R₀ постоянна, а
                R₁ = L₀ ⊕ F(R₀) суммируется в ноль при k ≥ 2. Насыщение
                младшей половины такого свойства не даёт и умирает сразу.
    r-half   -- младшая половина, для сравнения
    nibble   -- целые нибблы половины L (классическое насыщение нибблов)
    random   -- произвольные позиции по всему блоку
    """
    sets = []
    for _ in range(count):
        if mode == "l-half":
            sets.append(sorted(rng.sample(range(48, 96), min(k, 48))))
        elif mode == "r-half":
            sets.append(sorted(rng.sample(range(48), min(k, 48))))
        elif mode == "nibble":
            nib = rng.sample(range(12), max(1, k // 4))
            bits = [48 + 4 * nb + i for nb in nib for i in range(4)]
            sets.append(sorted(bits[:k]))
        else:
            sets.append(sorted(rng.sample(range(96), k)))
    return sets


def run_batch(backend, key, rounds, tasks, jobs):
    per = max(1, len(tasks) // jobs)
    chunks = [tasks[i:i + per] for i in range(0, len(tasks), per)]
    parts = parallel_map(_w_integral, [(key, rounds, c) for c in chunks], jobs)
    return [x for p in parts for x in p]


def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    parser.add_argument("--max-k", type=int, default=None,
                        help="largest subspace dimension to enumerate")
    parser.add_argument("--max-rounds", type=int, default=8)
    parser.add_argument("--trials", type=int, default=8,
                        help="independent (base point, active set) trials")
    args = parser.parse_args()

    backend = get_backend(args)
    jobs = jobs_of(args)
    scale = profile_scale(args)
    rng = random.Random(args.seed)
    key = bytes(rng.getrandbits(8) for _ in range(32))

    # 2^k шифрований на пробу; подбираем k под бюджет.
    default_k = {0.12: 20, 1.0: 24, 15.0: 27, 240.0: 30}
    max_k = args.max_k or (20 if scale < 0.5 else
                           24 if scale < 5 else
                           27 if scale < 50 else 30)
    trials = args.trials

    r = Reporter("Dedalyan integral cryptanalysis and algebraic degree")
    r.info(f"key {key[:8].hex()}...   max subspace dimension k = {max_k} "
           f"(2^{max_k} = {2**max_k:,} encryptions per probe)")
    r.info(f"trials per (k, rounds): {trials}   processes: {jobs}")

    v_int = RoundVerdict("integral (zero-sum) distinguisher")

    # ---- 1. Насыщение старшей половины (канонический интеграл Фейстеля) ---
    r.section("1. Zero-sum over subspaces of the L half (canonical Feistel "
              "integral)")
    r.info("sum == 0 for every trial  =>  integral distinguisher at that "
           "round count")
    r.info("a random permutation gives a zero sum with probability 2^-96, so "
           "even one clean zero counts")
    r.row(f"{'k':>3}  " + "  ".join(f"r{i}" .rjust(6)
                                    for i in range(1, args.max_rounds + 1)))

    balanced_depth = {}
    for k in range(2, max_k + 1, 2 if max_k <= 12 else 4):
        cells = []
        for rounds in range(1, args.max_rounds + 1):
            sets = active_sets(k, rng, trials, "l-half")
            tasks = [(rng.getrandbits(48), rng.getrandbits(48), s)
                     for s in sets]
            res = run_batch(backend, key, rounds, tasks, jobs)
            zero = sum(1 for sl, sr in res if sl == 0 and sr == 0)
            cells.append(f"{zero}/{trials}".rjust(6))
            if zero == trials:
                balanced_depth[k] = rounds
        r.row(f"{k:>3}  " + "  ".join(cells))

    # Для контраста -- насыщение младшей половины.
    r.info("")
    r.info("same table for the R half (expected to die at round 1):")
    cells = []
    for rounds in range(1, min(args.max_rounds, 4) + 1):
        sets = active_sets(min(max_k, 16), rng, trials, "r-half")
        tasks = [(rng.getrandbits(48), rng.getrandbits(48), s) for s in sets]
        res = run_batch(backend, key, rounds, tasks, jobs)
        zero = sum(1 for sl, sr in res if sl == 0 and sr == 0)
        cells.append(f"r{rounds}:{zero}/{trials}")
    r.row("  ".join(cells))

    r.section("Deepest zero-sum by subspace dimension")
    for k in sorted(balanced_depth):
        r.row(f"k = {k:>2}: balanced through round {balanced_depth[k]}")
    if balanced_depth:
        best_k = max(balanced_depth, key=lambda k: balanced_depth[k])
        depth = balanced_depth[best_k]
        thr = 0.0   # нулевая сумма либо есть, либо нет -- статистики не нужно
        v_int.add(depth, 1.0, thr, f"k = {best_k}")
        r.note(f"deepest integral distinguisher: round {depth} using "
               f"k = {best_k} active bits (2^{best_k} chosen plaintexts)")
        r.note(f"margin: {16 - depth} of 16 rounds")
    else:
        r.note("no zero-sum property found at any tested (k, round) pair")

    # ---- 2. Алгебраическая степень ---------------------------------------
    r.section("2. Algebraic degree per round")
    # Производная порядка k обнуляется, если степень МЕНЬШЕ k. Значит
    # информативен НАИБОЛЬШИЙ k с ненулевой суммой -- он даёт degree >= k.
    r.info("an order-k derivative vanishes iff the degree is BELOW k, so the")
    r.info("informative quantity is the LARGEST k with a non-zero sum: it")
    r.info("gives degree >= k. We scan k downwards and stop at the first hit.")
    r.row(f"{'rounds':>7}  {'degree lower bound':>20}  note")
    for rounds in range(1, args.max_rounds + 1):
        found = None
        for k in range(max_k, 0, -1):
            sets = active_sets(k, rng, max(2, trials // 2), "l-half")
            tasks = [(rng.getrandbits(48), rng.getrandbits(48), s)
                     for s in sets]
            res = run_batch(backend, key, rounds, tasks, jobs)
            if any(sl or sr for sl, sr in res):
                found = k
                break
        if found is None:
            r.row(f"{rounds:>7}  {'< 1':>20}  "
                  f"every derivative vanishes -- would mean a constant cipher")
        elif found == max_k:
            r.row(f"{rounds:>7}  {'>= ' + str(max_k):>20}  "
                  f"saturated at the tested ceiling; true degree may be higher")
        else:
            r.row(f"{rounds:>7}  {found:>20}  "
                  f"order {found + 1} and above all vanish")

    # ---- 3. Насыщение нибблов --------------------------------------------
    r.section("3. Nibble-saturation integrals")
    r.info("saturating whole nibbles is the classical integral setup and")
    r.info("often reaches one round deeper than arbitrary bit sets")
    for nnib in (1, 2, 3, 4, 5, 6):
        k = 4 * nnib
        if k > max_k:
            break
        depth = 0
        for rounds in range(1, args.max_rounds + 1):
            sets = active_sets(k, rng, trials, "nibble")
            tasks = [(rng.getrandbits(48), rng.getrandbits(48), s)
                     for s in sets]
            res = run_batch(backend, key, rounds, tasks, jobs)
            if all(sl == 0 and sr == 0 for sl, sr in res):
                depth = rounds
        r.row(f"{nnib} saturated nibbles (k = {k:>2}): balanced through "
              f"round {depth}")

    # ---- 4. Частичные нулевые суммы --------------------------------------
    r.section("4. Partial zero-sums (per output bit)")
    r.info("even when the full block sum is non-zero, individual output bits")
    r.info("may still be balanced -- a weaker but usable distinguisher")
    k = min(max_k, 24)
    for rounds in range(3, args.max_rounds + 1):
        acc_l = acc_r = 0
        reps = max(8, trials * 2)
        zero_bits = np.ones(96, dtype=bool)
        for _ in range(reps):
            s = active_sets(k, rng, 1, "l-half")[0]
            tasks = [(rng.getrandbits(48), rng.getrandbits(48), s)]
            (sl, sr), = run_batch(backend, key, rounds, tasks, jobs)
            word = (sl << 48) | sr
            for b in range(96):
                if (word >> b) & 1:
                    zero_bits[b] = False
        nz = int(zero_bits.sum())
        # У случайной перестановки каждый бит нулевой с вероятностью 2^-reps.
        r.row(f"rounds {rounds:>2}, k = {k}: {nz:>2} of 96 output bits "
              f"always balanced over {reps} trials "
              f"(random expectation {96 * 2.0**-reps:.2e})")

    if v_int.rows:
        v_int.report(r)
        secure_round_summary(r, [v_int])

    r.section("Interpretation")
    r.info("An integral distinguisher at round d means: with 2^k chosen")
    r.info("plaintexts an attacker distinguishes d-round Dedalyan from a")
    r.info("random permutation. Key recovery typically adds 2-3 rounds on")
    r.info("top of the distinguisher, so compare d + 3 against 16.")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
