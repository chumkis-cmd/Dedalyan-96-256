"""Бумеранг-атаки на Dedalyan: бумеранг, прямоугольник, йо-йо.

Бумеранг склеивает два коротких дифференциала вместо одного длинного.
Схема квартета:

    P1, P2 = P1 ⊕ α        ->   C1, C2
    C3 = C1 ⊕ δ, C4 = C2 ⊕ δ  ->   P3, P4  (расшифровкой)
    квартет «вернулся», если P3 ⊕ P4 == α

Для случайной перестановки это происходит с вероятностью 2^−96. Любая
заметная частота -- различитель. Вероятность бумеранга примерно p²q², где
p и q -- вероятности верхнего и нижнего дифференциалов, поэтому атака бьёт
глубже, чем каждый из них по отдельности.

Дополнительно проверяются:
* йо-йо-игра -- структурная версия того же приёма без вероятностей;
* усиленный бумеранг (прямоугольник) на структурах открытых текстов.

Запуск:  python attacks/boomerang.py
         python attacks/boomerang.py --profile deep --max-rounds 10
"""

from __future__ import annotations

import math
import random
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _lib import (MASK, Reporter, RoundVerdict, fmt_diff, get_backend,
                  jobs_of, low_weight_differences, make_parser,
                  parallel_map, profile_scale, random_differences,
                  secure_round_summary, split_work)

BASE_SAMPLES = 400_000


def _w_boomerang(task):
    key, rounds, al, ar, dl, dr, n, seed = task
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    return backend.boomerang(ctx, rounds, al, ar, dl, dr, n, seed), n


def _w_boomerang_multi(task):
    """Много комбинаций (alpha, delta) за один вызов.

    Раздавать по одной комбинации на вызов parallel_map нельзя: сериализация
    и диспетчеризация стоят дороже самой работы, когда комбинаций сотни.
    """
    key, rounds, combos, n, seed = task
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    out = []
    for i, (al, ar, dl, dr) in enumerate(combos):
        out.append(backend.boomerang(ctx, rounds, al, ar, dl, dr, n,
                                     seed + 7919 * i))
    return out


def _w_yoyo(task):
    """Йо-йо: меняем половины местами между парами и смотрим, сохраняется ли
    разность. Для 5-раундового Фейстеля это классический различитель."""
    key, rounds, n, seed = task
    import numpy as _np
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    g = _np.random.default_rng(seed)
    hits = 0
    batch = 50_000
    done = 0
    while done < n:
        m = min(batch, n - done)
        p1 = g.integers(0, 1 << 48, size=(m, 2), dtype=_np.uint64)
        p2 = p1.copy()
        p2[:, 1] = g.integers(0, 1 << 48, size=m, dtype=_np.uint64)  # общий L
        c1 = backend.encrypt_many(ctx, p1.copy(), rounds)
        c2 = backend.encrypt_many(ctx, p2.copy(), rounds)
        # Обмениваем правые половины шифротекстов и расшифровываем.
        c3 = c1.copy(); c3[:, 1] = c2[:, 1]
        c4 = c2.copy(); c4[:, 1] = c1[:, 1]
        q3 = backend.decrypt_many(ctx, c3, rounds)
        q4 = backend.decrypt_many(ctx, c4, rounds)
        hits += int(((q3[:, 0] == q4[:, 0])).sum())
        done += m
    return hits, done


def run_boomerang(backend, key, rounds, alpha, delta, n, seed, jobs):
    chunks = split_work(n, jobs)
    tasks = [(key, rounds, alpha[0], alpha[1], delta[0], delta[1], c,
              seed + 7919 * i) for i, c in enumerate(chunks)]
    parts = parallel_map(_w_boomerang, tasks, jobs)
    return sum(p[0] for p in parts), sum(p[1] for p in parts)


def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    parser.add_argument("--max-rounds", type=int, default=8)
    parser.add_argument("--pairs", type=int, default=None,
                        help="how many (alpha, delta) combinations to try")
    args = parser.parse_args()

    backend = get_backend(args)
    jobs = jobs_of(args)
    scale = profile_scale(args)
    rng = random.Random(args.seed)
    key = bytes(rng.getrandbits(8) for _ in range(32))

    n = max(50_000, int(BASE_SAMPLES * scale))
    npairs = args.pairs or max(12, int(48 * min(scale, 10)))

    r = Reporter("Dedalyan boomerang / rectangle / yoyo")
    r.info(f"key {key[:8].hex()}...   quartets per (alpha,delta) {n:,}   "
           f"processes {jobs}")
    r.info(f"random-permutation return rate: 2^-96 = {2.0**-96:.2e}")

    v_boom = RoundVerdict("boomerang")

    # ---- 1. Однобитовые верх/низ -----------------------------------------
    r.section("1. Single-bit alpha and delta")
    r.info("a returned quartet at a rate far above 2^-96 is a distinguisher")
    best_by_round = {}
    singles = [(0, 1 << b) for b in (0, 1, 7, 23, 24, 47)] + \
              [(1 << b, 0) for b in (0, 1, 7, 23, 24, 47)]
    combos = [(a[0], a[1], d[0], d[1]) for a in singles for d in singles]
    per_combo = max(n // 8, 20_000)
    for rounds in range(3, args.max_rounds + 1):
        # Комбинации раздаются пачками по процессам, а не по одной.
        chunk = max(1, (len(combos) + jobs - 1) // jobs)
        tasks = [(key, rounds, combos[i:i + chunk], per_combo,
                  args.seed + 101 * rounds + i)
                 for i in range(0, len(combos), chunk)]
        counts = [c for part in parallel_map(_w_boomerang_multi, tasks, jobs)
                  for c in part]
        bi = int(np.argmax(counts))
        best = counts[bi]
        best_pair = ((combos[bi][0], combos[bi][1]),
                     (combos[bi][2], combos[bi][3])) if best else None
        total_used = per_combo
        rate = best / total_used if total_used else 0.0
        best_by_round[rounds] = (best, total_used, best_pair)
        # Порог: ожидание случайной перестановки ничтожно, поэтому любой
        # повторяющийся возврат значим. Берём порог Пуассона.
        r.row(f"rounds {rounds:>2}  best {best:>6} returns of {total_used:,}  "
              f"rate {rate:.3e}  " +
              (f"{fmt_diff(*best_pair[0])} / {fmt_diff(*best_pair[1])}"
               if best_pair else ""))
        v_boom.add(rounds, rate, 4.0 / max(total_used, 1),
                   fmt_diff(*best_pair[0]) if best_pair else "")

    # ---- 2. Подтверждение -------------------------------------------------
    r.section("2. Confirmation on fresh quartets")
    r.info("noise does not survive a rerun with a different seed")
    for rounds in sorted(best_by_round):
        hits, tot, pair = best_by_round[rounds]
        if hits == 0 or pair is None:
            r.row(f"rounds {rounds:>2}  nothing to confirm")
            continue
        h2, t2 = run_boomerang(backend, key, rounds, pair[0], pair[1], n * 2,
                               args.seed + 888_888 + rounds, jobs)
        r.row(f"rounds {rounds:>2}  first {hits}/{tot:,}  "
              f"rerun {h2}/{t2:,}  rate {h2 / t2:.3e}  "
              f"{'CONFIRMED' if h2 > 0 else 'not reproduced'}")

    # ---- 3. Поиск по кандидатам -------------------------------------------
    r.section(f"3. Search over {npairs} random (alpha, delta) pairs")
    lows = low_weight_differences(max_weight=2, limit=npairs)
    rands = random_differences(npairs, rng)
    pool = lows + rands
    search_combos = [(a[0], a[1]) + rng.choice(pool)
                     for a in lows[:npairs // 2] + rands[:npairs // 2]]
    per = max(n // 16, 10_000)
    for rounds in range(4, args.max_rounds + 1):
        chunk = max(1, (len(search_combos) + jobs - 1) // jobs)
        tasks = [(key, rounds, search_combos[i:i + chunk], per,
                  args.seed + 17 * rounds + i)
                 for i in range(0, len(search_combos), chunk)]
        counts = [c for part in parallel_map(_w_boomerang_multi, tasks, jobs)
                  for c in part]
        found = sum(1 for c in counts if c > 0)
        r.row(f"rounds {rounds:>2}  {found} of {len(search_combos)} pairs "
              f"returned at least one quartet; best count {max(counts)}")

    # ---- 4. Йо-йо ---------------------------------------------------------
    r.section("4. Yoyo game (structural, no probabilities involved)")
    r.info("swap ciphertext halves between two texts sharing a half,")
    r.info("decrypt, and check whether the shared half survives")
    nyoyo = max(50_000, int(200_000 * min(scale, 10)))
    for rounds in range(2, min(args.max_rounds, 8) + 1):
        chunks = split_work(nyoyo, jobs)
        tasks = [(key, rounds, c, args.seed + 53 * rounds + i)
                 for i, c in enumerate(chunks)]
        parts = parallel_map(_w_yoyo, tasks, jobs)
        hits = sum(p[0] for p in parts)
        tot = sum(p[1] for p in parts)
        rate = hits / tot
        expected = 2.0 ** -48
        r.row(f"rounds {rounds:>2}  {hits:>8} / {tot:,} = {rate:.3e}   "
              f"(random {expected:.2e})  "
              f"{'DISTINGUISHER' if rate > 100 * expected else 'no'}")

    # ---- 5. Прямоугольник -------------------------------------------------
    r.section("5. Amplified boomerang (rectangle) estimate")
    r.info("a rectangle attack over m texts yields about m^2/2 * p^2 q^2 / 2^n")
    r.info("right quartets; with no measurable p, q the estimate is vacuous,")
    r.info("which is itself the result worth recording")
    for rounds in sorted(best_by_round):
        hits, tot, _ = best_by_round[rounds]
        if hits:
            p = hits / tot
            m_needed = math.sqrt(2.0 / p) if p > 0 else float("inf")
            r.row(f"rounds {rounds:>2}  observed boomerang probability "
                  f"{p:.3e} -> about 2^{math.log2(m_needed):.1f} texts "
                  f"for one rectangle quartet")
        else:
            r.row(f"rounds {rounds:>2}  no returned quartet: probability "
                  f"below {1.0 / tot:.2e}, rectangle not applicable")

    v_boom.report(r)
    secure_round_summary(r, [v_boom])
    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
