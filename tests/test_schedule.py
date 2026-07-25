"""Расписание ключей: лавина, эквивалентные ключи, связанные ключи, лабиринты.

Покрывает раздел 10.2 («Расписание ключей») и сверяется с показателями
раздела 9. Дополнительно проверяется само проектное утверждение из раздела 11:
без прогрева лавина для k0 падает примерно до 17%.

Идеальное стандартное отклонение доли для 48-битного подключа:
sqrt(48 * 0.25) / 48 = 7.22%.

Запуск:  python tests/test_schedule.py
         python tests/test_schedule.py --profile deep
"""

from __future__ import annotations

import math
import random
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dedalyan as D
from dedalyan_harness import (Reporter, autoscale, get_backend, jobs_of,
                              make_parser, noise_threshold, parallel_map,
                              split_work)

SUBKEY_BITS = 48
IDEAL_SIGMA = math.sqrt(SUBKEY_BITS * 0.25) / SUBKEY_BITS   # 0.0722

SPEC_SUBKEY_AVALANCHE = {0: (48.94, 7.65), 1: (49.95, 7.24),
                         8: (50.36, 7.32), 15: (50.17, 7.14)}
SPEC_CIPHER_AVALANCHE = (50.08, 5.23)
SPEC_LAB_FIXPOINTS = 1.68          # в среднем на 32 позиции
SPEC_EQUIV_KEYS_TESTED = 80_006
SPEC_REPEAT_KEYS_TESTED = 20_000

DEFAULT_AVALANCHE_N = 200_000
DEFAULT_EQUIV_N = 2_000_000
DEFAULT_LAB_N = 200_000


# --------------------------------------------------------------------------
# Расписание без прогрева -- для проверки утверждения раздела 11
# --------------------------------------------------------------------------

def key_schedule_no_warmup(K: int):
    """То же расписание, но шаги i = -4..-1 пропущены."""
    KL, S = D.split_key(K)
    T = D.build_labyrinth(KL)
    ks = []
    for i in range(0, D.N):
        S = [D.apply_labyrinth(v, T) for v in S]
        for j in range(4):
            S[j] = (S[j] + S[(j + 1) % 4]) & D.M
        rot = (2 * (i % 24) + 5) % D.W
        S = [D.rotl(v, rot) for v in S]
        S = [D.apply_labyrinth(v, T) for v in S]
        ks.append((S[i % 4] + D.round_constant(i)) & D.M)
    return ks


# --------------------------------------------------------------------------
# Рабочие функции для процессов
# --------------------------------------------------------------------------

def _w_subkey_avalanche(task):
    seed, chunk = task
    from dedalyan_c import backend
    s1, s2 = backend.subkey_avalanche(chunk, seed)
    return chunk, np.array(s1, dtype=object), np.array(s2, dtype=object)


def _w_key_avalanche(task):
    seed, chunk, rounds = task
    from dedalyan_c import backend
    return backend.key_avalanche(rounds, chunk, seed).astype(np.uint64)


def _w_fingerprint(task):
    seed, chunk, rounds = task
    from dedalyan_c import backend
    return backend.key_fingerprint(rounds, 0, 0, chunk, seed)


def _w_subkey_dump(task):
    seed, chunk = task
    from dedalyan_c import backend
    return backend.subkey_dump(chunk, seed)


def _w_fixpoints(task):
    seed, chunk = task
    from dedalyan_c import backend
    return np.bincount(backend.labyrinth_fixpoints(chunk, seed), minlength=33)


def _w_relkey(task):
    seed, chunk, rounds, dk = task
    from dedalyan_c import backend
    return backend.relkey_bitcount(rounds, dk, chunk, seed)


# --------------------------------------------------------------------------

def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    args = parser.parse_args()
    backend = get_backend(args)
    jobs = jobs_of(args)
    rounds = args.rounds or D.N
    rng = random.Random(args.seed)
    scale = {"quick": 0.1, "standard": 1.0, "deep": 10.0,
             "overnight": 100.0}[args.profile]
    if args.samples:
        scale = args.samples / DEFAULT_AVALANCHE_N

    r = Reporter("Dedalyan key schedule -- avalanche, equivalences, labyrinths")
    r.info(f"processes: {jobs}   scale: x{scale:g}   rounds: {rounds}")
    r.info(f"ideal subkey sigma: {IDEAL_SIGMA * 100:.2f}%  (48-bit subkey)")

    # ---- 1. Лавина по мастер-ключу для каждого подключа ------------------
    n = max(2000, int(DEFAULT_AVALANCHE_N * scale))
    r.section(f"1. Master-key avalanche per subkey ({n:,} random key pairs)")
    chunks = split_work(n, jobs)
    tasks = [(args.seed + 31 * i, c) for i, c in enumerate(chunks)]
    parts = parallel_map(_w_subkey_avalanche, tasks, jobs)
    total = sum(p[0] for p in parts)
    s1 = np.zeros(16, dtype=object)
    s2 = np.zeros(16, dtype=object)
    for _, a, b in parts:
        s1 = s1 + a
        s2 = s2 + b

    r.row(f"{'subkey':>7}  {'mean':>8}  {'sigma':>8}  {'spec mean':>10}  "
          f"{'spec sigma':>10}")
    means = []
    for j in range(16):
        m = float(s1[j]) / total
        v = max(0.0, float(s2[j]) / total - m * m)
        mean, sigma = m / SUBKEY_BITS, math.sqrt(v) / SUBKEY_BITS
        means.append(mean)
        sm, ss = SPEC_SUBKEY_AVALANCHE.get(j, (None, None))
        r.row(f"k[{j:2d}]   {mean * 100:7.2f}%  {sigma * 100:7.2f}%  "
              f"{('%9.2f%%' % sm) if sm else '         -'}  "
              f"{('%9.2f%%' % ss) if ss else '         -'}")

    tol = max(1.0, 400.0 * IDEAL_SIGMA / math.sqrt(total))
    for j, (sm, _ss) in sorted(SPEC_SUBKEY_AVALANCHE.items()):
        r.check(abs(means[j] * 100 - sm) <= tol,
                f"k[{j}] mean within {tol:.2f}pp of spec {sm}%",
                f"got {means[j] * 100:.2f}%")
    worst = max(range(16), key=lambda j: abs(means[j] - 0.5))
    r.check(abs(means[worst] - 0.5) < 0.02,
            "every subkey has avalanche within 2pp of 50%",
            f"worst k[{worst}] = {means[worst] * 100:.2f}%")

    # ---- 2. Необходимость прогрева ---------------------------------------
    r.section("2. Warm-up is load-bearing (design claim, spec section 11)")
    nw = max(300, int(3000 * min(scale, 1.0)))
    tot_w = tot_nw = 0
    for _ in range(nw):
        k = rng.getrandbits(256)
        bit = rng.randrange(256)
        k2 = k ^ (1 << bit)
        tot_w += bin(D.key_schedule(k)[0] ^ D.key_schedule(k2)[0]).count("1")
        tot_nw += bin(key_schedule_no_warmup(k)[0] ^
                      key_schedule_no_warmup(k2)[0]).count("1")
    av_w = tot_w / nw / SUBKEY_BITS
    av_nw = tot_nw / nw / SUBKEY_BITS
    r.info(f"k[0] avalanche with warm-up   : {av_w * 100:6.2f}%  ({nw} samples)")
    r.info(f"k[0] avalanche without warm-up: {av_nw * 100:6.2f}%")
    r.check(abs(av_w - 0.5) < 0.03, "with warm-up k[0] reaches ~50%",
            f"{av_w * 100:.2f}%")
    r.check(av_nw < 0.35, "without warm-up k[0] is clearly degraded",
            f"{av_nw * 100:.2f}% (spec section 11 says ~17%)")

    # ---- 3. Лавина по ключу через весь шифр ------------------------------
    n3 = max(200, int(2000 * scale))
    r.section(f"3. Key avalanche through the full cipher ({n3:,} keys x 256 bits)")
    chunks = split_work(n3, jobs)
    tasks = [(args.seed + 101 * i, c, rounds) for i, c in enumerate(chunks)]
    mats = parallel_map(_w_key_avalanche, tasks, jobs)
    acc = np.zeros((256, 96), dtype=np.uint64)
    for m in mats:
        acc += m
    trials = sum(t[1] for t in tasks)
    frac = acc.astype(np.float64) / trials          # доля по каждой паре бит
    mean = frac.mean()
    # Ст. откл. доли перевёрнутых бит на один эксперимент.
    per_bit = frac.mean(axis=1)
    r.info(f"mean over all 256x96 bit pairs: {mean * 100:.3f}%")
    r.info(f"per key-bit avalanche: min {per_bit.min() * 100:.2f}%, "
           f"max {per_bit.max() * 100:.2f}%")
    r.check(abs(mean * 100 - SPEC_CIPHER_AVALANCHE[0]) < 1.0,
            f"matches spec {SPEC_CIPHER_AVALANCHE[0]}%", f"{mean * 100:.2f}%")
    thr = noise_threshold(trials, tests=256 * 96)
    off = int((np.abs(frac - 0.5) > thr).sum())
    r.check(off == 0,
            f"no (key bit, out bit) pair biased beyond {thr:.4f}",
            f"{off} of 24576 pairs off (Bonferroni-corrected)")

    # ---- 4. Эквивалентные ключи ------------------------------------------
    n4 = max(50_000, int(DEFAULT_EQUIV_N * scale))
    r.section(f"4. Equivalent keys ({n4:,} random keys, E_K(0) collisions)")
    chunks = split_work(n4, jobs)
    tasks = [(args.seed + 977 * i, c, rounds) for i, c in enumerate(chunks)]
    fps = np.concatenate(parallel_map(_w_fingerprint, tasks, jobs))
    packed = (fps[:, 0].astype(object) << 48) | fps[:, 1].astype(object)
    uniq = len(set(packed.tolist()))
    dup = len(packed) - uniq
    expected = len(packed) ** 2 / 2 / (2.0 ** 96)
    r.info(f"tested {len(packed):,} keys (spec tested {SPEC_EQUIV_KEYS_TESTED:,})")
    r.info(f"birthday expectation at 96-bit output: {expected:.2e} collisions")
    r.check(dup == 0, "no two keys encrypt 0 to the same ciphertext",
            f"{dup} collisions")

    # ---- 5. Повторяющиеся подключи ---------------------------------------
    n5 = max(5_000, int(SPEC_REPEAT_KEYS_TESTED * scale))
    r.section(f"5. Repeated subkeys within one schedule ({n5:,} keys)")
    chunks = split_work(n5, jobs)
    tasks = [(args.seed + 613 * i, c) for i, c in enumerate(chunks)]
    dumps = np.concatenate(parallel_map(_w_subkey_dump, tasks, jobs))
    repeats = sum(1 for row in dumps if len(set(row.tolist())) != 16)
    exp_rep = len(dumps) * (16 * 15 / 2) / (2.0 ** 48)
    r.info(f"birthday expectation: {exp_rep:.2e} keys with a repeat")
    r.check(repeats == 0, "no schedule repeats a subkey", f"{repeats} cases")
    # Подключи не должны быть равны нулю или маске -- вырожденные состояния.
    degenerate = int(((dumps == 0) | (dumps == D.M)).sum())
    r.check(degenerate == 0, "no subkey is all-zero or all-ones",
            f"{degenerate} cases")

    # ---- 6. Вырожденные лабиринты ----------------------------------------
    n6 = max(20_000, int(DEFAULT_LAB_N * scale))
    r.section(f"6. Degenerate labyrinths ({n6:,} random K_L)")
    chunks = split_work(n6, jobs)
    tasks = [(args.seed + 389 * i, c) for i, c in enumerate(chunks)]
    hist = sum(parallel_map(_w_fixpoints, tasks, jobs))
    tot = int(hist.sum())
    mean_fp = float((hist * np.arange(33)).sum()) / tot
    r.info(f"mean fixed points over 32 positions: {mean_fp:.3f} "
           f"(spec {SPEC_LAB_FIXPOINTS}, random permutation 2.0)")
    r.info("distribution: " +
           " ".join(f"{i}:{hist[i]}" for i in range(9) if hist[i]))
    r.check(abs(mean_fp - SPEC_LAB_FIXPOINTS) < 0.15,
            f"matches spec {SPEC_LAB_FIXPOINTS}", f"got {mean_fp:.3f}")
    # Полностью тождественная таблица означала бы бесполезный лабиринт.
    r.check(int(hist[32]) == 0, "no key yields two identity tables",
            f"{int(hist[32])} cases")

    # ---- 7. Связанные ключи ----------------------------------------------
    n7 = max(20_000, int(200_000 * scale))
    r.section(f"7. Related keys ({n7:,} pairs per difference)")
    diffs = [
        ("single bit in K_0 (lsb)", bytes(31) + bytes([1])),
        ("single bit in K_L (msb)", bytes([0x80]) + bytes(31)),
        ("all ones", bytes([0xFF]) * 32),
        ("K_L only", bytes([0xFF]) * 8 + bytes(24)),
        ("K_0 only", bytes(26) + bytes([0xFF]) * 6),
    ]
    worst_z = 0.0
    for name, dk in diffs:
        chunks = split_work(n7, jobs)
        tasks = [(args.seed + 53 * i, c, rounds, dk)
                 for i, c in enumerate(chunks)]
        cnt = sum(parallel_map(_w_relkey, tasks, jobs))
        trials = sum(t[1] for t in tasks)
        frac = cnt.astype(np.float64) / trials
        thr = noise_threshold(trials, tests=96 * len(diffs))
        bad = int((np.abs(frac - 0.5) > thr).sum())
        z = float(np.abs(frac - 0.5).max() / (0.5 / math.sqrt(trials)))
        worst_z = max(worst_z, z)
        r.row(f"{name:<24} mean {frac.mean() * 100:6.2f}%  "
              f"max|bias| {np.abs(frac - 0.5).max():.5f}  "
              f"biased bits {bad}/96")
    r.check(worst_z < 6.0,
            "no output bit shows a related-key bias beyond 6 sigma",
            f"worst {worst_z:.2f} sigma")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
