"""Дифференциальный криптоанализ Dedalyan.

Что проверяется:

1. Матрица смещений 96x96: для каждой однобитовой входной разности -- смещение
   вероятности переворота каждого выходного бита, по раундам.
2. Поиск лучшей разности: случайные и малого веса Хэмминга кандидаты,
   отбор по максимальному смещению.
3. Точная дифференциальная вероятность для лучших пар (Δin -> Δout).
4. Усечённые дифференциалы на уровне нибблов.
5. Дифференциально-линейные различители: разность на входе, линейная маска
   на выходе -- часто пробивают на 1-2 раунда глубже чистого дифференциала.

Спецификация (раздел 9) сообщает: смещение 0.5000 на раунде 3 (структурное
свойство Фейстеля), затем 0.0347 / 0.0360 / 0.0370 при пороге шума 0.027.
Порог 0.027 соответствует примерно 5 000 пар. Здесь выборки на несколько
порядков больше, поэтому и порог шума ниже -- сравнивать надо не абсолютные
числа, а отношение «смещение / порог».

Запуск:  python attacks/differential.py
         python attacks/differential.py --profile deep --max-rounds 8
"""

from __future__ import annotations

import math
import random
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _lib import (BLOCK_BITS, Reporter, RoundVerdict, fmt_diff, get_backend,
                  jobs_of, low_weight_differences, make_parser,
                  noise_threshold, parallel_map, profile_scale,
                  random_differences, secure_round_summary,
                  single_bit_differences, split_work)

BASE_SAMPLES = 200_000


# --------------------------------------------------------------------------
# Рабочие функции (верхний уровень модуля: нужны для multiprocessing)
# --------------------------------------------------------------------------

def _w_bitcount(task):
    """Считает смещения выходных бит для списка входных разностей."""
    key, rounds, diffs, n, seed = task
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    out = np.zeros((len(diffs), 96), dtype=np.float64)
    for i, (dl, dr) in enumerate(diffs):
        cnt = backend.diff_bitcount(ctx, rounds, dl, dr, n, seed + 7919 * i)
        out[i] = cnt.astype(np.float64) / n
    return out


def _w_nibble_seen(task):
    key, rounds, diffs, n, seed = task
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    acc = np.zeros((len(diffs), 24, 16), dtype=bool)
    for i, (dl, dr) in enumerate(diffs):
        acc[i] = backend.diff_nibble_seen(ctx, rounds, dl, dr, n,
                                          seed + 104729 * i).astype(bool)
    return acc


def _w_exact(task):
    key, rounds, dl, dr, ol, orr, n, seed = task
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    return backend.diff_exact(ctx, rounds, dl, dr, ol, orr, n, seed)


def _w_difflin(task):
    """Дифференциально-линейный: разность на входе, маска на выходе.

    Считает Pr[<β, C ⊕ C'> = 0] для набора масок β.
    """
    key, rounds, dl, dr, masks, n, seed = task
    import numpy as _np
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    rng = _np.random.default_rng(seed)
    hits = _np.zeros(len(masks), dtype=_np.int64)
    batch = 100_000
    done = 0
    while done < n:
        m = min(batch, n - done)
        p = rng.integers(0, 1 << 48, size=(m, 2), dtype=_np.uint64)
        q = p.copy()
        q[:, 0] ^= _np.uint64(dl)
        q[:, 1] ^= _np.uint64(dr)
        c1 = backend.encrypt_many(ctx, p, rounds)
        c2 = backend.encrypt_many(ctx, q, rounds)
        dl_out = c1[:, 0] ^ c2[:, 0]
        dr_out = c1[:, 1] ^ c2[:, 1]
        for i, (ml, mr) in enumerate(masks):
            v = (dl_out & _np.uint64(ml)) ^ (dr_out & _np.uint64(mr))
            # Чётность 64-битного слова.
            x = v
            for s in (32, 16, 8, 4, 2, 1):
                x = x ^ (x >> _np.uint64(s))
            hits[i] += int((x & _np.uint64(1)) .sum())
        done += m
    return hits, done


# --------------------------------------------------------------------------

def bias_matrix(backend, key, rounds, diffs, n, seed, jobs):
    """Матрица (len(diffs), 96) вероятностей переворота выходных бит."""
    per = max(1, len(diffs) // jobs)
    tasks = []
    for i in range(0, len(diffs), per):
        chunk = diffs[i:i + per]
        tasks.append((key, rounds, chunk, n, seed + 1_000_003 * i))
    parts = parallel_map(_w_bitcount, tasks, jobs)
    return np.concatenate(parts, axis=0)


def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    parser.add_argument("--max-rounds", type=int, default=8,
                        help="highest round count to analyse")
    parser.add_argument("--candidates", type=int, default=None,
                        help="random input differences to try in phase 2")
    args = parser.parse_args()

    backend = get_backend(args)
    jobs = jobs_of(args)
    scale = profile_scale(args)
    rng = random.Random(args.seed)
    key = bytes(rng.getrandbits(8) for _ in range(32))

    n = max(20_000, int(BASE_SAMPLES * scale))
    ncand = args.candidates or max(64, int(512 * min(scale, 20)))

    r = Reporter("Dedalyan differential cryptanalysis")
    r.info(f"key {key[:8].hex()}...   samples/difference {n:,}   "
           f"processes {jobs}")
    r.info(f"analysing rounds 1..{args.max_rounds} of 16")

    singles = single_bit_differences()
    v_single = RoundVerdict("single-bit differential")
    v_search = RoundVerdict("searched differential")
    best_single = {}      # лучшие кандидаты фазы 1, для масштабного теста

    # ---- фаза 1: однобитовые разности ------------------------------------
    r.section("1. Single-bit input differences (96 x 96 bias matrix)")
    r.row(f"{'rounds':>7}  {'max bias':>10}  {'noise':>9}  {'ratio':>7}  "
          f"{'#above':>7}  worst (din -> out bit)")
    for rounds in range(1, args.max_rounds + 1):
        probs = bias_matrix(backend, key, rounds, singles, n,
                            args.seed + 31 * rounds, jobs)
        bias = np.abs(probs - 0.5)
        thr = noise_threshold(n, tests=96 * 96)
        idx = np.unravel_index(int(np.argmax(bias)), bias.shape)
        best = float(bias[idx])
        above = int((bias > thr).sum())
        dl, dr = singles[idx[0]]
        wit = f"{fmt_diff(dl, dr)} -> bit {idx[1]}"
        best_single[rounds] = (dl, dr, int(idx[1]), best)
        v_single.add(rounds, best, thr, wit)
        r.row(f"{rounds:>7}  {best:10.6f}  {thr:9.6f}  {best / thr:7.2f}  "
              f"{above:>7}  {wit}")
        # Дальше идти незачем: раз уж на этом раунде всё в шуме,
        # на следующем тем более.
        if best <= thr and rounds >= 6:
            break

    # ---- фаза 2: поиск по кандидатам -------------------------------------
    r.section(f"2. Search over {ncand} candidate differences "
              f"(low weight + random)")
    cands = low_weight_differences(max_weight=2, limit=ncand // 2)
    cands += random_differences(ncand - len(cands), rng)
    r.info(f"{len(cands)} candidates: Hamming weight 1-2 plus random")

    best_overall = {}
    for rounds in range(3, args.max_rounds + 1):
        probs = bias_matrix(backend, key, rounds, cands, max(n // 4, 10_000),
                            args.seed + 977 * rounds, jobs)
        nn = max(n // 4, 10_000)
        bias = np.abs(probs - 0.5)
        thr = noise_threshold(nn, tests=len(cands) * 96)
        idx = np.unravel_index(int(np.argmax(bias)), bias.shape)
        best = float(bias[idx])
        dl, dr = cands[idx[0]]
        wit = f"{fmt_diff(dl, dr)} -> bit {idx[1]}"
        best_overall[rounds] = (dl, dr, int(idx[1]), best)
        v_search.add(rounds, best, thr, wit)
        r.row(f"rounds {rounds:>2}  best bias {best:.6f}  noise {thr:.6f}  "
              f"ratio {best / thr:5.2f}  {wit}")

    # ---- фаза 3: масштабный тест -----------------------------------------
    r.section("3. Scaling test -- the decisive check")
    r.info("A real bias stays put as the sample grows; noise shrinks as")
    r.info("1/sqrt(n). We remeasure each candidate at n, 10n and 100n on")
    r.info("fresh seeds and look at how the value moves. This separates a")
    r.info("genuine characteristic from the maximum of 9216 noisy estimates,")
    r.info("which a single rerun cannot do.")
    r.row(f"{'source':<10}{'rounds':>7}  {'bias@n':>10}  {'bias@10n':>10}  "
          f"{'bias@100n':>10}  {'decay':>7}  verdict")
    scaling_jobs = ([("single", rr) + best_single[rr]
                     for rr in sorted(best_single)] +
                    [("searched", rr) + best_overall[rr]
                     for rr in sorted(best_overall)])
    confirmed_depth = 0
    for source, rounds, dl, dr, bit, _first in scaling_jobs:
        vals = []
        base = max(n // 4, 20_000)
        for mult, tag in ((1, "a"), (10, "b"), (100, "c")):
            nn = base * mult
            m = bias_matrix(backend, key, rounds, [(dl, dr)], nn,
                            args.seed + 555_555 + rounds + 7 * mult, jobs)
            vals.append(float(abs(m[0, bit] - 0.5)))
        # Чистый шум даёт vals[0]/vals[2] = 10; настоящее смещение -- около 1.
        decay = vals[0] / vals[2] if vals[2] > 0 else float("inf")
        thr = noise_threshold(base * 100, tests=1)
        if vals[2] > thr and decay < 3.0:
            verdict = "REAL BIAS"
            confirmed_depth = max(confirmed_depth, rounds)
        elif vals[2] > thr:
            verdict = "marginal"
        else:
            verdict = "noise"
        r.row(f"{source:<10}{rounds:>7}  {vals[0]:10.6f}  {vals[1]:10.6f}  "
              f"{vals[2]:10.6f}  {decay:7.2f}  {verdict}")
    r.info("decay ~10 means pure noise (shrinks as 1/sqrt(n));")
    r.info("decay ~1 with a value above the floor means a real bias")
    r.note(f"deepest CONFIRMED differential bias: round {confirmed_depth} "
           f"of 16 (margin {16 - confirmed_depth} rounds)")

    # ---- фаза 4: точная дифференциальная вероятность ---------------------
    r.section("4. Exact differential probability for the round-3 structure")
    r.info("after 3 Feistel rounds an input difference (0, d) forces "
           "L_out = d deterministically -- this is geometry, not weakness")
    dl, dr = 0, 1
    nexact = max(100_000, int(1_000_000 * min(scale, 5)))
    for rounds in (2, 3, 4):
        # Для round<=3 ожидаем детерминированную связь по половине блока.
        probs = bias_matrix(backend, key, rounds, [(dl, dr)], nexact,
                            args.seed + 4242, jobs)
        det = int((np.abs(probs[0] - 0.5) > 0.4999).sum())
        r.row(f"rounds {rounds}: {det:>2} of 96 output bits are "
              f"deterministic given input difference {fmt_diff(dl, dr)}")

    # ---- фаза 5: усечённые дифференциалы ---------------------------------
    r.section("5. Truncated (nibble-level) differentials")
    r.info("a nibble difference value never observed = impossible truncated "
           "differential")
    ntrunc = max(20_000, int(200_000 * min(scale, 10)))
    tdiffs = singles[:24]
    for rounds in range(2, min(args.max_rounds, 6) + 1):
        per = max(1, len(tdiffs) // jobs)
        tasks = [(key, rounds, tdiffs[i:i + per], ntrunc,
                  args.seed + 13 * rounds + i)
                 for i in range(0, len(tdiffs), per)]
        seen = np.concatenate(parallel_map(_w_nibble_seen, tasks, jobs), axis=0)
        # Сколько (разность, позиция ниббла, значение) ни разу не встретилось.
        missing = int((~seen).sum())
        total = seen.size
        # Ожидание для случайной функции: 16 значений, ntrunc проб.
        exp_missing = total * math.exp(-ntrunc / 16.0)
        r.row(f"rounds {rounds}: {missing:>6} of {total} nibble differences "
              f"never seen (random expectation {exp_missing:.2e})")

    # ---- фаза 6: дифференциально-линейный --------------------------------
    r.section("6. Differential-linear distinguisher")
    r.info("input difference + output linear mask; often reaches deeper "
           "than a plain differential")
    ndl = max(50_000, int(400_000 * min(scale, 10)))
    masks = [(0, 1 << i) for i in range(0, 48, 4)] + \
            [(1 << i, 0) for i in range(0, 48, 4)] + \
            [(0xFFFFFFFFFFFF, 0xFFFFFFFFFFFF), (0, 0xFFFFFFFFFFFF)]
    v_dl = RoundVerdict("differential-linear")
    for rounds in range(3, args.max_rounds + 1):
        chunks = split_work(ndl, jobs)
        tasks = [(key, rounds, 0, 1, masks, c, args.seed + 61 * rounds + i)
                 for i, c in enumerate(chunks)]
        parts = parallel_map(_w_difflin, tasks, jobs)
        hits = sum(p[0] for p in parts)
        tot = sum(p[1] for p in parts)
        frac = hits.astype(np.float64) / tot
        bias = np.abs(frac - 0.5)
        thr = noise_threshold(tot, tests=len(masks))
        bi = int(np.argmax(bias))
        v_dl.add(rounds, float(bias[bi]), thr, f"mask #{bi}")
        r.row(f"rounds {rounds:>2}  max bias {bias[bi]:.6f}  "
              f"noise {thr:.6f}  ratio {bias[bi] / thr:5.2f}")

    # ---- вердикты --------------------------------------------------------
    v_single.report(r)
    v_search.report(r)
    v_dl.report(r)
    secure_round_summary(r, [v_single, v_search, v_dl])

    r.section("Interpretation")
    r.info("Rounds 1-3: deterministic relations are expected in ANY Feistel")
    r.info("network -- after r rounds one half is a known function of the")
    r.info("input halves. They are not an attack.")
    r.info("What matters is the first round where NO deviation exceeds the")
    r.info("noise floor, and how much margin the full 16 rounds leave.")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
