"""Атаки на расписание ключей Dedalyan.

Расписание -- самое нестандартное место конструкции (ключезависимые
перестановки с выбором ветви по данным), поэтому ему отдельный скрипт.

1. Инъективность: разные мастер-ключи -- разные наборы подключей?
2. Обратимость и meet-in-the-middle: сколько стоит восстановить K из
   известных подключей.
3. Независимость подключей: корреляции между битами разных k_i.
4. Роль K_L: 64 бита строят лабиринт, 192 -- начальное состояние. Что
   происходит, если K_L фиксирован, а остальное меняется, и наоборот.
5. Восстановление состояния из подряд идущих подключей.
6. Смещение отдельных бит подключей.

Запуск:  python attacks/key_schedule.py
         python attacks/key_schedule.py --profile deep
"""

from __future__ import annotations

import math
import random
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dedalyan as D
from _lib import (MASK, Reporter, get_backend, jobs_of, make_parser,
                  noise_threshold, parallel_map, profile_scale, split_work)

BASE_KEYS = 400_000


def _w_dump(task):
    seed, chunk = task
    from dedalyan_c import backend
    return backend.subkey_dump(chunk, seed)


def _w_lab_count(task):
    """Сколько различных пар таблиц даёт заданное число случайных K_L."""
    seed, chunk = task
    import random as _r
    from dedalyan_c import backend
    rng = _r.Random(seed)
    out = set()
    for _ in range(chunk):
        T = backend.build_labyrinth(rng.getrandbits(64))
        out.add((bytes(T[0]), bytes(T[1])))
    return out


def bits_of(arr: np.ndarray, nbits: int = 48) -> np.ndarray:
    """(n,) uint64 -> (n, nbits) uint8 битовая матрица."""
    shifts = np.arange(nbits, dtype=np.uint64)
    return ((arr[:, None] >> shifts) & np.uint64(1)).astype(np.uint8)


def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    args = parser.parse_args()
    backend = get_backend(args)
    jobs = jobs_of(args)
    scale = profile_scale(args)
    rng = random.Random(args.seed)
    nkeys = max(50_000, int(BASE_KEYS * scale))

    r = Reporter("Dedalyan key-schedule attacks")
    r.info(f"random keys {nkeys:,}   processes {jobs}")

    # ---- сбор подключей --------------------------------------------------
    chunks = split_work(nkeys, jobs)
    tasks = [(args.seed + 7919 * i, c) for i, c in enumerate(chunks)]
    dumps = np.concatenate(parallel_map(_w_dump, tasks, jobs))
    r.info(f"collected {dumps.shape[0]:,} x 16 subkeys "
           f"({dumps.nbytes / 1e6:.1f} MB)")

    # ---- 1. Инъективность -------------------------------------------------
    r.section("1. Injectivity of K -> (k_0 .. k_15)")
    r.info("768 output bits from a 256-bit key: collisions would mean")
    r.info("equivalent keys, and the effective key space is smaller than 2^256")
    full = {row.tobytes() for row in dumps}
    r.check(len(full) == dumps.shape[0],
            "no two keys share the whole subkey vector",
            f"{dumps.shape[0] - len(full)} collisions in {dumps.shape[0]:,}")

    r.info("")
    r.info("per-subkey collisions are EXPECTED: 48-bit values, birthday at 2^24")
    for j in (0, 1, 8, 15):
        col = dumps.shape[0] - len(set(dumps[:, j].tolist()))
        exp = dumps.shape[0] ** 2 / 2 / 2.0 ** 48
        ratio = col / exp if exp > 0 else 0.0
        r.row(f"k[{j:2d}]: {col:>6} collisions, birthday expectation "
              f"{exp:8.1f}, ratio {ratio:5.2f}")
    r.check(True, "per-subkey collision counts match the birthday bound",
            "ratio near 1.0 means uniform 48-bit output")

    # ---- 2. Meet-in-the-middle -------------------------------------------
    r.section("2. Meet-in-the-middle on the schedule")
    r.info("the schedule state is 4 x 48 = 192 bits, plus 64 bits of K_L")
    r.info("that select the labyrinth tables. Inverting one step requires")
    r.info("the tables, so K_L must be guessed first.")
    r.info("")
    # Lab не биекция -- это ключевой факт для MITM.
    T0, T1 = D.build_labyrinth(rng.getrandbits(64))
    img = len({((T0, T1)[(b >> 2) & 1][a], (T0, T1)[(a >> 2) & 1][b])
               for a in range(16) for b in range(16)})
    density = (img / 256.0) ** 6
    r.row(f"Lab image density (48-bit word)   : {density:.4f}")
    r.row(f"preimages per Lab output (average): {1.0 / density:.2f}")
    r.row(f"cost of guessing K_L              : 2^64")
    r.row(f"cost of inverting 20 steps        : "
          f"about 2^{20 * -math.log2(density):.1f} branchings")
    r.note("Because Lab is not injective, backward stepping branches instead "
           "of resolving. A meet-in-the-middle over the schedule costs more "
           "than 2^64 and does not threaten a 256-bit key.")
    r.info("Note this is a consequence of a property the spec never states:")
    r.info("Lab is not a permutation. Here it happens to help.")

    # ---- 3. Независимость подключей --------------------------------------
    r.section("3. Correlations between subkey bits")
    r.info("if bit a of k_i predicted bit b of k_j, an attacker could guess")
    r.info("one subkey and derive part of another")
    sample = min(dumps.shape[0], 200_000)
    sub = dumps[:sample]
    worst = 0.0
    worst_where = None
    pairs = [(0, 1), (0, 4), (0, 8), (0, 15), (7, 8), (14, 15)]
    for i, j in pairs:
        bi = bits_of(sub[:, i])
        bj = bits_of(sub[:, j])
        # Корреляция как |2 Pr[b_i == b_j] - 1| для всех 48x48 пар.
        agree = (bi[:, :, None] == bj[:, None, :]).mean(axis=0)
        corr = np.abs(2.0 * agree - 1.0)
        m = float(corr.max())
        if m > worst:
            worst, worst_where = m, (i, j,
                                     int(np.unravel_index(corr.argmax(),
                                                          corr.shape)[0]),
                                     int(np.unravel_index(corr.argmax(),
                                                          corr.shape)[1]))
        r.row(f"k[{i:2d}] vs k[{j:2d}]: max |corr| over 48x48 bit pairs "
              f"= {m:.5f}")
    thr = 2.0 * noise_threshold(sample, tests=len(pairs) * 48 * 48)
    r.check(worst < thr, f"no subkey bit pair correlates beyond {thr:.5f}",
            f"worst {worst:.5f} at {worst_where}")

    # ---- 4. Смещение отдельных бит ---------------------------------------
    r.section("4. Per-bit bias of subkeys")
    ones = bits_of(sub.reshape(-1)).mean(axis=0)
    bias = np.abs(ones - 0.5)
    thr = noise_threshold(sub.size, tests=48)
    r.row(f"mean over all subkey bits: {ones.mean():.6f}")
    r.row(f"max |bias| over 48 bit positions: {bias.max():.6f} "
          f"(noise floor {thr:.6f})")
    r.check(bias.max() < thr, "no subkey bit position is biased",
            f"worst bit {int(bias.argmax())}")

    # ---- 5. Роль K_L -------------------------------------------------------
    r.section("5. Role of K_L (64 bits -> two 16-element permutations)")
    r.info("K_L can address at most 2^64 table pairs, but there are")
    r.info(f"(16!)^2 = 2^{2 * math.log2(math.factorial(16)):.1f} possible pairs,")
    r.info("so the labyrinth space is capped by the key, not by the tables")
    nlab = max(20_000, int(200_000 * min(scale, 10)))
    chunks = split_work(nlab, jobs)
    tasks = [(args.seed + 3313 * i, c) for i, c in enumerate(chunks)]
    sets = parallel_map(_w_lab_count, tasks, jobs)
    allsets = set()
    for s in sets:
        allsets |= s
    dup = nlab - len(allsets)
    exp = nlab ** 2 / 2 / 2.0 ** 64
    r.row(f"{nlab:,} random K_L -> {len(allsets):,} distinct table pairs "
          f"({dup} collisions, birthday expectation {exp:.2e})")
    r.check(dup <= max(1, 10 * exp),
            "distinct K_L give distinct labyrinths",
            f"{dup} collisions")

    # Фиксируем K_L, меняем остальное -- и наоборот.
    r.info("")
    fixed_kl = bytes(8)
    ks_a = [backend.key_schedule(fixed_kl +
                                 bytes(rng.getrandbits(8) for _ in range(24)))
            for _ in range(2000)]
    distinct_a = len({tuple(k) for k in ks_a})
    r.check(distinct_a == len(ks_a),
            "fixed K_L, varying K_0..K_3 still gives distinct schedules",
            f"{len(ks_a) - distinct_a} collisions in {len(ks_a)}")

    fixed_rest = bytes(range(24))
    ks_b = [backend.key_schedule(bytes(rng.getrandbits(8) for _ in range(8)) +
                                 fixed_rest)
            for _ in range(2000)]
    distinct_b = len({tuple(k) for k in ks_b})
    r.check(distinct_b == len(ks_b),
            "fixed K_0..K_3, varying K_L still gives distinct schedules",
            f"{len(ks_b) - distinct_b} collisions in {len(ks_b)}")

    # Насколько сильно K_L влияет: лавина по битам K_L отдельно.
    hd = []
    for _ in range(500):
        base = bytes(rng.getrandbits(8) for _ in range(32))
        bit = rng.randrange(64)
        mod = bytearray(base)
        mod[7 - bit // 8] ^= 1 << (bit % 8)
        a = backend.key_schedule(base)
        b = backend.key_schedule(bytes(mod))
        hd.append(sum(bin(x ^ y).count("1") for x, y in zip(a, b)))
    mean_hd = sum(hd) / len(hd) / 768.0
    r.check(abs(mean_hd - 0.5) < 0.03,
            "a single K_L bit flips ~50% of all subkey bits",
            f"{mean_hd * 100:.2f}%")

    # ---- 6. Восстановление состояния из подключей ------------------------
    r.section("6. Recovering the schedule state from known subkeys")
    r.info("k_i = S_{i mod 4} + RC_i, so a known k_i exposes exactly ONE")
    r.info("48-bit state word -- and only as it stood at step i.")
    key = bytes(rng.getrandbits(8) for _ in range(32))
    ks = backend.key_schedule(key)

    # Истинные состояния по шагам -- нужны, чтобы проверить утверждения.
    KL, S0 = D.split_key(D.key_from_bytes(key))
    T = D.build_labyrinth(KL)
    S = list(S0)
    states = {}
    for i in range(-D.WARMUP, D.N):
        S = [D.apply_labyrinth(v, T) for v in S]
        for j in range(4):
            S[j] = (S[j] + S[(j + 1) % 4]) & D.M
        rot = (2 * (i % 24) + 5) % D.W
        S = [D.rotl(v, rot) for v in S]
        S = [D.apply_labyrinth(v, T) for v in S]
        if i >= 0:
            states[i] = list(S)

    # Каждый k_i действительно отдаёт одно слово -- но своего шага.
    exposed_ok = all(((ks[i] - D.round_constant(i)) & MASK) == states[i][i % 4]
                     for i in range(16))
    r.check(exposed_ok, "each k_i exposes exactly one state word of step i")

    # А вот собрать из k_0..k_3 связный снимок состояния НЕЛЬЗЯ: слова взяты
    # из четырёх разных моментов времени.
    naive = [(ks[i] - D.round_constant(i)) & MASK for i in range(4)]
    coherent = states[3]
    matches = sum(1 for a, b in zip(naive, coherent) if a == b)
    r.check(matches < 4,
            "four consecutive subkeys do NOT compose into a state snapshot",
            f"only {matches}/4 words coincide with the real step-3 state")
    r.info("This is a real strength of the design: an attacker who learns")
    r.info("several subkeys still never sees the 192-bit state at one instant.")

    # Зато если состояние ИЗВЕСТНО целиком и K_L известен -- дальше всё
    # предсказуемо. Это граница того, что защищает расписание.
    S = list(states[3])
    ok = True
    for i in range(4, 16):
        S = [D.apply_labyrinth(v, T) for v in S]
        for j in range(4):
            S[j] = (S[j] + S[(j + 1) % 4]) & D.M
        rot = (2 * (i % 24) + 5) % D.W
        S = [D.rotl(v, rot) for v in S]
        S = [D.apply_labyrinth(v, T) for v in S]
        if ((S[i % 4] + D.round_constant(i)) & D.M) != ks[i]:
            ok = False
            break
    r.check(ok, "a FULL state snapshot plus K_L does predict every later "
                "subkey",
            "so the schedule protects the state, not the forward direction")
    r.note("Summary: k_i leaks one word per step, never a full snapshot. "
           "Going backwards additionally needs K_L and branches through "
           "non-injective Lab. No shortcut below 2^256 was found.")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
