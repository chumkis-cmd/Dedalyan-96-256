"""Линейный криптоанализ Dedalyan с произвольными масками.

Раздел 0 спецификации прямо указывает линейный криптоанализ с произвольными
масками как непроверенный. Здесь он проверяется в четырёх режимах:

1. Все пары однобитовых масок: 96 x 96 корреляций по раундам.
2. Случайные плотные и разреженные маски.
3. Направленный поиск (восхождение по холму с перезапусками): из случайной
   маски переворачиваются отдельные биты, изменение принимается, если
   корреляция выросла. Это находит то, чего не найдёт равномерный перебор:
   пространство масок имеет размер 2^192, случайная выборка покрывает нулевую
   его долю.
4. Свойства неподвижных компонент: корреляции умножения на γ₁, δ, γ₂ и
   таблиц лабиринта -- источник любых линейных характеристик шифра.

Измеряется корреляция c = 2·|Pr[<α,P> ⊕ <β,C> = 0] − 1/2|. Для случайной
перестановки |c| ≈ 1/sqrt(n) при n текстах; данные атаки требуют примерно
c^−2 текстов, поэтому корреляция 2^−48 и ниже неатакуема при 96-битном блоке.

Запуск:  python attacks/linear.py
         python attacks/linear.py --profile deep --max-rounds 8
"""

from __future__ import annotations

import math
import random
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _lib import (MASK, Reporter, RoundVerdict, get_backend, jobs_of,
                  make_parser, noise_threshold, parallel_map, profile_scale,
                  random_masks, secure_round_summary, single_bit_masks,
                  split_work)

BASE_SAMPLES = 400_000


# --------------------------------------------------------------------------
# Рабочие функции
# --------------------------------------------------------------------------

def _w_linear(task):
    """counts[i] для набора масок на одном потоке текстов."""
    key, rounds, masks, n, seed = task
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    arr = np.array(masks, dtype=np.uint64)
    return backend.linear_pairs(ctx, rounds, arr, n, seed), n


def evaluate(backend, key, rounds, masks, n, seed, jobs):
    """Корреляции |2p - 1| для списка масок (in_l, in_r, out_l, out_r)."""
    if not masks:
        return np.zeros(0), 0
    chunks = split_work(n, jobs)
    tasks = [(key, rounds, masks, c, seed + 7919 * i)
             for i, c in enumerate(chunks)]
    parts = parallel_map(_w_linear, tasks, jobs)
    counts = sum(p[0].astype(np.int64) for p in parts)
    total = sum(p[1] for p in parts)
    p = counts.astype(np.float64) / total
    return np.abs(2.0 * p - 1.0), total


def mask_str(m) -> str:
    return (f"a={m[0]:012x}:{m[1]:012x} b={m[2]:012x}:{m[3]:012x}")


def flip_bit(mask, idx):
    """Переворачивает бит idx (0..191) в четвёрке масок."""
    m = list(mask)
    word, bit = divmod(idx, 48)
    m[word] ^= (1 << bit)
    return tuple(m)


# --------------------------------------------------------------------------
# Анализ неподвижных компонент
# --------------------------------------------------------------------------

def multiplier_correlations(mult: int, nbits: int = 48, trials: int = 200_000,
                            seed: int = 1):
    """Корреляции однобитовых линейных приближений x -> (x·mult) mod 2^48.

    Умножение на нечётную константу -- биекция, но далеко не случайная
    перестановка: младшие биты произведения линейны по младшим битам входа.
    """
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 1 << 48, size=trials, dtype=np.uint64)
    y = (x * np.uint64(mult)) & np.uint64(MASK)
    best = 0.0
    best_pair = None
    for i in range(nbits):
        bi = ((x >> np.uint64(i)) & np.uint64(1)).astype(np.int8)
        for j in range(nbits):
            bj = ((y >> np.uint64(j)) & np.uint64(1)).astype(np.int8)
            p = float(np.mean(bi == bj))
            c = abs(2.0 * p - 1.0)
            if c > best:
                best, best_pair = c, (i, j)
    return best, best_pair


def labyrinth_linearity(T):
    """Максимальная корреляция линейного приближения 4-битной таблицы.

    Для случайной перестановки 4 бит типичное значение около 0.5;
    величина 1.0 означала бы линейную (то есть бесполезную) таблицу.
    """
    best = 0.0
    best_mask = None
    for a in range(1, 16):
        for b in range(1, 16):
            s = 0
            for x in range(16):
                pa = bin(a & x).count("1") & 1
                pb = bin(b & T[x]).count("1") & 1
                s += 1 if pa == pb else -1
            c = abs(s) / 16.0
            if c > best:
                best, best_mask = c, (a, b)
    return best, best_mask


# --------------------------------------------------------------------------

def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    parser.add_argument("--max-rounds", type=int, default=8)
    parser.add_argument("--restarts", type=int, default=None,
                        help="hill-climbing restarts in phase 3")
    args = parser.parse_args()

    backend = get_backend(args)
    jobs = jobs_of(args)
    scale = profile_scale(args)
    rng = random.Random(args.seed)
    key = bytes(rng.getrandbits(8) for _ in range(32))

    n = max(50_000, int(BASE_SAMPLES * scale))
    restarts = args.restarts or max(4, int(12 * min(scale, 20)))

    r = Reporter("Dedalyan linear cryptanalysis (arbitrary masks)")
    r.info(f"key {key[:8].hex()}...   samples/mask {n:,}   processes {jobs}")
    r.info(f"random-permutation correlation floor ~ 1/sqrt(n) = "
           f"{1.0 / math.sqrt(n):.6f}")

    v_single = RoundVerdict("single-bit linear")
    v_random = RoundVerdict("random-mask linear")
    v_search = RoundVerdict("hill-climbed linear")
    best_single = {}      # лучшие маски фаз 1 и 2 -- для масштабного теста
    best_random = {}

    # ---- фаза 0: неподвижные компоненты ----------------------------------
    r.section("0. Fixed components (source of every linear characteristic)")
    for name, mult in (("gamma1 0x46BD0CD0DCAD", 0x46BD0CD0DCAD),
                       ("delta  0x128F8FB70F", 0x128F8FB70F),
                       ("gamma2 0x46BB83114CCF", 0x46BB83114CCF)):
        c, pair = multiplier_correlations(mult, trials=100_000,
                                          seed=args.seed)
        r.row(f"{name:<26} max single-bit correlation {c:.4f} at bits {pair}")
    r.info("correlation 1.0 at (0,0) is inherent: the lowest bit of an odd")
    r.info("multiple always equals the lowest bit of the input")

    T0, T1 = backend.build_labyrinth(int.from_bytes(key[:8], "big"))
    c0, m0 = labyrinth_linearity(T0)
    c1, m1 = labyrinth_linearity(T1)
    r.row(f"labyrinth T0: max linear correlation {c0:.4f} at masks {m0}")
    r.row(f"labyrinth T1: max linear correlation {c1:.4f} at masks {m1}")
    r.check(c0 < 1.0 and c1 < 1.0, "labyrinth tables are non-linear")

    # ---- фаза 1: однобитовые маски ---------------------------------------
    r.section("1. All single-bit mask pairs (96 x 96)")
    r.row(f"{'rounds':>7}  {'max |corr|':>11}  {'noise':>9}  {'ratio':>7}  "
          f"{'#above':>7}")
    singles = single_bit_masks()
    pairs = [(a[0], a[1], b[0], b[1]) for a in singles for b in singles]
    for rounds in range(1, args.max_rounds + 1):
        corr, tot = evaluate(backend, key, rounds, pairs, max(n // 8, 20_000),
                             args.seed + 41 * rounds, jobs)
        thr = 2.0 * noise_threshold(tot, tests=len(pairs))
        best = float(corr.max())
        above = int((corr > thr).sum())
        bi = int(np.argmax(corr))
        best_single[rounds] = pairs[bi]
        v_single.add(rounds, best, thr, mask_str(pairs[bi]))
        r.row(f"{rounds:>7}  {best:11.6f}  {thr:9.6f}  {best / thr:7.2f}  "
              f"{above:>7}")
        if best <= thr and rounds >= 6:
            break

    # ---- фаза 2: случайные маски -----------------------------------------
    r.section("2. Random masks (dense and sparse)")
    cand = []
    for w in (2, 3, 4, 6):
        a = random_masks(60, rng, weight=w)
        b = random_masks(60, rng, weight=w)
        cand += [(x[0], x[1], y[0], y[1]) for x, y in zip(a, b)]
    a = random_masks(120, rng)
    b = random_masks(120, rng)
    cand += [(x[0], x[1], y[0], y[1]) for x, y in zip(a, b)]
    r.info(f"{len(cand)} mask pairs: Hamming weights 2/3/4/6 plus dense")
    for rounds in range(3, args.max_rounds + 1):
        corr, tot = evaluate(backend, key, rounds, cand, n,
                             args.seed + 733 * rounds, jobs)
        thr = 2.0 * noise_threshold(tot, tests=len(cand))
        best = float(corr.max())
        bi = int(np.argmax(corr))
        best_random[rounds] = cand[bi]
        v_random.add(rounds, best, thr, mask_str(cand[bi]))
        r.row(f"rounds {rounds:>2}  max |corr| {best:.6f}  noise {thr:.6f}  "
              f"ratio {best / thr:5.2f}")

    # ---- фаза 3: направленный поиск --------------------------------------
    r.section(f"3. Hill climbing over the mask space ({restarts} restarts)")
    r.info("the mask space is 2^192; uniform sampling covers none of it, so "
           "we climb")
    search_n = max(20_000, n // 16)
    for rounds in range(4, args.max_rounds + 1):
        global_best = 0.0
        global_mask = None
        for restart in range(restarts):
            cur = (rng.getrandbits(48), rng.getrandbits(48),
                   rng.getrandbits(48), rng.getrandbits(48))
            cur_c = float(evaluate(backend, key, rounds, [cur], search_n,
                                   args.seed + restart, jobs)[0][0])
            improved = True
            steps = 0
            while improved and steps < 6:
                improved = False
                steps += 1
                # Пробуем перевернуть каждый из 192 бит, батчем.
                neigh = [flip_bit(cur, i) for i in range(192)]
                cs, _ = evaluate(backend, key, rounds, neigh, search_n,
                                 args.seed + 100 * restart + steps, jobs)
                bi = int(np.argmax(cs))
                if float(cs[bi]) > cur_c:
                    cur, cur_c = neigh[bi], float(cs[bi])
                    improved = True
            if cur_c > global_best:
                global_best, global_mask = cur_c, cur
        # Подтверждение на большой независимой выборке.
        conf, tot = evaluate(backend, key, rounds, [global_mask], n * 4,
                             args.seed + 987_654 + rounds, jobs)
        thr = 2.0 * noise_threshold(tot, tests=1)
        v_search.add(rounds, float(conf[0]), thr, mask_str(global_mask))
        r.row(f"rounds {rounds:>2}  climbed to {global_best:.6f}  "
              f"confirmed {float(conf[0]):.6f}  noise {thr:.6f}  "
              f"{'REAL' if float(conf[0]) > thr else 'noise'}")

    # ---- фаза 3b: масштабный тест ----------------------------------------
    r.section("3b. Scaling test -- the decisive check")
    r.info("Phases 1 and 2 report the MAXIMUM over thousands of noisy")
    r.info("estimates. That maximum routinely clears a Bonferroni threshold,")
    r.info("which assumes independent tests, so a raw hit there is a")
    r.info("candidate and not a finding. A real correlation holds its value")
    r.info("as n grows; noise shrinks as 1/sqrt(n). We remeasure at n, 10n")
    r.info("and 100n with fresh seeds.")
    v_conf = RoundVerdict("confirmed linear")
    r.row(f"{'source':<10}{'rounds':>7}  {'corr@n':>10}  {'corr@10n':>10}  "
          f"{'corr@100n':>10}  {'decay':>7}  verdict")
    scaling = ([("single", rr, best_single[rr]) for rr in sorted(best_single)] +
               [("random", rr, best_random[rr]) for rr in sorted(best_random)])
    for source, rounds, mask in scaling:
        vals = []
        base = max(n // 4, 25_000)
        for mult in (1, 10, 100):
            c, tot = evaluate(backend, key, rounds, [mask], base * mult,
                              args.seed + 424_242 + rounds + 13 * mult, jobs)
            vals.append(float(c[0]))
        decay = vals[0] / vals[2] if vals[2] > 0 else float("inf")
        thr = 2.0 * noise_threshold(base * 100, tests=1)
        if vals[2] > thr and decay < 3.0:
            verdict = "REAL"
            v_conf.add(rounds, vals[2], thr, mask_str(mask))
        elif vals[2] > thr:
            verdict = "marginal"
        else:
            verdict = "noise"
        r.row(f"{source:<10}{rounds:>7}  {vals[0]:10.6f}  {vals[1]:10.6f}  "
              f"{vals[2]:10.6f}  {decay:7.2f}  {verdict}")
    r.info("")
    r.info("Only rows marked REAL count as findings. Rows that clear the")
    r.info("phase-1 threshold but collapse here were order-statistic noise.")

    # ---- фаза 4: оценка требуемых данных ---------------------------------
    r.section("4. Data requirement implied by the best confirmed correlation")
    r.info("a linear attack needs about c^-2 known plaintexts; the whole")
    r.info("codebook is 2^96 blocks, so c below 2^-48 is unreachable")
    for v in (v_single, v_random, v_search):
        last = v.last_detected
        if last is None:
            continue
        row = [x for x in v.rows if x[0] == last][0]
        c = row[1]
        if c > 0:
            need = math.log2(1.0 / (c * c))
            r.row(f"{v.name:<24} round {last}: |c| = {c:.6f} -> "
                  f"2^{need:.1f} texts "
                  f"({'feasible' if need < 96 else 'beyond the codebook'})")

    v_single.rows and v_single.report(r)
    v_random.report(r)
    v_search.report(r)
    v_conf.report(r)
    r.info("The three tables above list CANDIDATES. Only 'confirmed linear'")
    r.info("survived the scaling test, and it drives the margin below.")
    secure_round_summary(r, [v_conf])

    r.section("Interpretation")
    r.info("Rounds 1-3 must show correlation 1.0: in a Feistel network one")
    r.info("output half is literally an input half. This is geometry.")
    r.info("The number that matters is the first round at which even a")
    r.info("directed search cannot beat the noise floor.")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
