"""Атаки на связанных ключах: дифференциалы, бумеранг, ротационный анализ.

Спецификация в разделе 11 сама указывает на прецедент: расписание AES-256
без достаточного перемешивания стало основой атаки Бирюкова--Ховратовича на
связанных ключах. Здесь тот же класс проверяется для Dedalyan.

1. Дифференциалы на связанных ключах: фиксированная разность ΔK, случайные
   ключи, смещение выходных бит по раундам.
2. Распространение ΔK по расписанию: сколько бит подключа меняется на каждом
   шаге. Если разность «застревает» -- это ровно та дыра, что была в AES-256.
3. Бумеранг на связанных ключах: два ключа сверху, два снизу. Самый опасный
   вариант, именно он ломал AES-256.
4. Ротационный криптоанализ: ARX-конструкции естественно уважают вращения,
   если константы подобраны неудачно. Проверяется Pr[E(x⋘r) = E(x)⋘r]
   с вращением ключа и без.
5. Ротационно-разностный (RX) анализ.

Запуск:  python attacks/related_key.py
         python attacks/related_key.py --profile deep
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
from _lib import (MASK, Reporter, RoundVerdict, get_backend, jobs_of,
                  make_parser, noise_threshold, parallel_map, profile_scale,
                  secure_round_summary, split_work)

BASE_SAMPLES = 300_000


# --------------------------------------------------------------------------

def _w_relkey(task):
    key_diff, rounds, n, seed = task
    from dedalyan_c import backend
    return backend.relkey_bitcount(rounds, key_diff, n, seed), n


def _w_rk_boomerang(task):
    """Бумеранг на связанных ключах.

    Верхняя пара использует K и K' = K ⊕ ΔK, нижняя -- те же ключи крест-накрест.
    Квартет возвращается, если P3 ⊕ P4 == α.
    """
    dk, rounds, al, ar, dl, dr, n, seed = task
    import numpy as _np
    import random as _r
    from dedalyan_c import backend
    rng = _r.Random(seed)
    g = _np.random.default_rng(seed)
    hits = 0
    done = 0
    batch = 20_000
    while done < n:
        m = min(batch, n - done)
        key = bytes(rng.getrandbits(8) for _ in range(32))
        key2 = bytes(a ^ b for a, b in zip(key, dk))
        c_a = backend.new_ctx(key)
        c_b = backend.new_ctx(key2)

        p1 = g.integers(0, 1 << 48, size=(m, 2), dtype=_np.uint64)
        p2 = p1.copy()
        p2[:, 0] ^= _np.uint64(al)
        p2[:, 1] ^= _np.uint64(ar)

        e1 = backend.encrypt_many(c_a, p1.copy(), rounds)
        e2 = backend.encrypt_many(c_b, p2.copy(), rounds)

        e3 = e1.copy(); e3[:, 0] ^= _np.uint64(dl); e3[:, 1] ^= _np.uint64(dr)
        e4 = e2.copy(); e4[:, 0] ^= _np.uint64(dl); e4[:, 1] ^= _np.uint64(dr)

        q3 = backend.decrypt_many(c_b, e3, rounds)
        q4 = backend.decrypt_many(c_a, e4, rounds)

        hits += int((((q3[:, 0] ^ q4[:, 0]) == _np.uint64(al)) &
                     ((q3[:, 1] ^ q4[:, 1]) == _np.uint64(ar))).sum())
        done += m
    return hits, done


def _w_rotational(task):
    rounds, rot, key_rot, n, seed = task
    from dedalyan_c import backend
    return backend.rotational(rounds, rot, key_rot, n, seed), n


# --------------------------------------------------------------------------

def schedule_difference_trace(dk_bytes: bytes, trials: int,
                              rng: random.Random):
    """Сколько бит состояния расписания различается на каждом шаге.

    Считается на Python: нужно заглянуть ВНУТРЬ расписания, а C отдаёт
    только готовые подключи.
    """
    steps = D.WARMUP + D.N
    acc = np.zeros(steps, dtype=np.float64)
    dk = int.from_bytes(dk_bytes, "big")
    for _ in range(trials):
        k1 = rng.getrandbits(256)
        k2 = k1 ^ dk
        states = []
        for K in (k1, k2):
            KL, S = D.split_key(K)
            T = D.build_labyrinth(KL)
            trace = []
            for i in range(-D.WARMUP, D.N):
                S = [D.apply_labyrinth(v, T) for v in S]
                for j in range(4):
                    S[j] = (S[j] + S[(j + 1) % 4]) & D.M
                rot = (2 * (i % 24) + 5) % D.W
                S = [D.rotl(v, rot) for v in S]
                S = [D.apply_labyrinth(v, T) for v in S]
                trace.append(list(S))
            states.append(trace)
        for i in range(steps):
            hd = sum(bin(a ^ b).count("1")
                     for a, b in zip(states[0][i], states[1][i]))
            acc[i] += hd
    return acc / trials / 192.0        # доля от 192 бит состояния


# --------------------------------------------------------------------------

def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    parser.add_argument("--max-rounds", type=int, default=8)
    args = parser.parse_args()

    backend = get_backend(args)
    jobs = jobs_of(args)
    scale = profile_scale(args)
    rng = random.Random(args.seed)
    n = max(50_000, int(BASE_SAMPLES * scale))

    r = Reporter("Dedalyan related-key and rotational cryptanalysis")
    r.info(f"samples per configuration {n:,}   processes {jobs}")

    v_rk = RoundVerdict("related-key differential")
    v_rot = RoundVerdict("rotational")

    diffs = [
        ("1 bit in K_0", bytes(31) + bytes([0x01])),
        ("1 bit in K_3", bytes(8) + bytes([0x80]) + bytes(23)),
        ("1 bit in K_L", bytes([0x80]) + bytes(31)),
        ("K_L all ones", bytes([0xFF]) * 8 + bytes(24)),
        ("K_0 all ones", bytes(26) + bytes([0xFF]) * 6),
        ("everything", bytes([0xFF]) * 32),
        ("alternating", bytes([0xAA]) * 32),
    ]

    # ---- 1. Дифференциалы на связанных ключах ----------------------------
    r.section("1. Related-key differentials through the full cipher")
    r.row(f"{'difference':<16}  " +
          "  ".join(f"r{i}".rjust(8) for i in range(2, args.max_rounds + 1)))
    for name, dk in diffs:
        cells = []
        worst = 0.0
        for rounds in range(2, args.max_rounds + 1):
            chunks = split_work(n, jobs)
            tasks = [(dk, rounds, c, args.seed + 13 * rounds + i)
                     for i, c in enumerate(chunks)]
            parts = parallel_map(_w_relkey, tasks, jobs)
            cnt = sum(p[0].astype(np.int64) for p in parts)
            tot = sum(p[1] for p in parts)
            frac = cnt.astype(np.float64) / tot
            bias = float(np.abs(frac - 0.5).max())
            worst = max(worst, bias)
            thr = noise_threshold(tot, tests=96 * len(diffs))
            cells.append((f"{bias:.5f}" + ("*" if bias > thr else "")).rjust(8))
        r.row(f"{name:<16}  " + "  ".join(cells))
    r.info("* marks a bias above the Bonferroni-corrected noise floor")

    # Отдельно -- вердикт по раундам на худшей разности.
    for rounds in range(2, args.max_rounds + 1):
        best = 0.0
        wit = ""
        for name, dk in diffs:
            chunks = split_work(n, jobs)
            tasks = [(dk, rounds, c, args.seed + 991 * rounds + i)
                     for i, c in enumerate(chunks)]
            parts = parallel_map(_w_relkey, tasks, jobs)
            cnt = sum(p[0].astype(np.int64) for p in parts)
            tot = sum(p[1] for p in parts)
            bias = float(np.abs(cnt.astype(np.float64) / tot - 0.5).max())
            if bias > best:
                best, wit = bias, name
        thr = noise_threshold(n, tests=96 * len(diffs))
        v_rk.add(rounds, best, thr, wit)

    # ---- 2. Распространение ΔK по расписанию -----------------------------
    r.section("2. How a key difference spreads through the schedule")
    r.info("this is the AES-256 failure mode: a difference that stays small")
    r.info("for several steps lets an attacker control the subkeys")
    trials = max(20, int(200 * min(scale, 5)))
    r.row(f"{'difference':<16}  " +
          "  ".join(f"s{i}".rjust(6) for i in range(-4, 6)) + "   ...  s15")
    for name, dk in diffs[:5]:
        trace = schedule_difference_trace(dk, trials, rng)
        cells = "  ".join(f"{v * 100:5.1f}" for v in trace[:10])
        r.row(f"{name:<16}  {cells}   ...  {trace[-1] * 100:5.1f}")
    r.info("values are % of the 192-bit schedule state that differs")
    r.info("50% from the first working step onwards is what we want to see")

    # ---- 3. Бумеранг на связанных ключах ---------------------------------
    r.section("3. Related-key boomerang (the Biryukov-Khovratovich class)")
    r.info("this is the attack that broke AES-256; a returned quartet rate")
    r.info("above 2^-96 would be a genuine break")
    nb = max(20_000, int(100_000 * min(scale, 10)))
    combos = [
        ("dK = 1 bit, alpha = 1 bit", bytes(31) + bytes([1]), (0, 1), (0, 1)),
        ("dK = K_L bit, alpha = 0", bytes([0x80]) + bytes(31), (0, 0), (0, 1)),
        ("dK = 1 bit, alpha = 0", bytes(31) + bytes([1]), (0, 0), (0, 1)),
    ]
    for name, dk, alpha, delta in combos:
        for rounds in (4, 6, 8):
            if rounds > args.max_rounds:
                continue
            chunks = split_work(nb, jobs)
            tasks = [(dk, rounds, alpha[0], alpha[1], delta[0], delta[1], c,
                      args.seed + 37 * rounds + i)
                     for i, c in enumerate(chunks)]
            parts = parallel_map(_w_rk_boomerang, tasks, jobs)
            hits = sum(p[0] for p in parts)
            tot = sum(p[1] for p in parts)
            r.row(f"{name:<28} rounds {rounds:>2}  "
                  f"{hits:>6} / {tot:,} = {hits / tot:.3e}  "
                  f"(random {2.0**-96:.2e})")

    # ---- 4. Ротационный криптоанализ -------------------------------------
    r.section("4. Rotational cryptanalysis")
    r.info("ARX ciphers can respect rotations: Pr[E(x<<<r) = E(x)<<<r] should")
    r.info("be 2^-96, and modular addition alone preserves rotations with")
    r.info("probability (1 + 2^-r + ...)/4 per operation, so constants matter")
    nr = max(50_000, int(200_000 * min(scale, 10)))
    r.row(f"{'rot':>4}  {'key rotated':>12}  {'rounds':>7}  "
          f"{'hits':>8}  {'rate':>12}")
    for rot in (1, 3, 8, 16, 24):
        for key_rot in (False, True):
            for rounds in (4, 8, args.max_rounds):
                chunks = split_work(nr, jobs)
                tasks = [(rounds, rot, 1 if key_rot else 0, c,
                          args.seed + 7 * rot + i)
                         for i, c in enumerate(chunks)]
                parts = parallel_map(_w_rotational, tasks, jobs)
                hits = sum(p[0] for p in parts)
                tot = sum(p[1] for p in parts)
                if hits or rounds == args.max_rounds:
                    r.row(f"{rot:>4}  {str(key_rot):>12}  {rounds:>7}  "
                          f"{hits:>8}  {hits / tot:12.3e}")
                if rounds == 4:
                    v_rot.add(rounds, hits / tot, 4.0 / tot, f"rot {rot}")

    # ---- 5. Ротационно-разностный (RX) -----------------------------------
    r.section("5. Rotational-XOR sanity")
    r.info("RX-differences generalise rotational pairs by allowing a constant")
    r.info("XOR offset; the round constants RC_i are what should break them")
    rc_rot = [D.round_constant(i) for i in range(16)]
    for rot in (1, 3, 8):
        # Если RC_i были бы вращательно-инвариантны, RX-характеристики
        # проходили бы бесплатно.
        inv = sum(1 for v in rc_rot if D.rotl(v, rot) == v)
        r.check(inv == 0,
                f"no round constant is invariant under rotation by {rot}",
                f"{inv} of 16")
    # То же для множителей.
    for name, v in (("gamma1", D.GAMMA1), ("delta", D.DELTA),
                    ("gamma2", D.GAMMA2), ("phi", D.PHI)):
        inv = [s for s in range(1, 48) if D.rotl(v, s) == v]
        r.check(not inv, f"{name} has no rotational symmetry",
                f"invariant under {inv}" if inv else "")

    v_rk.report(r)
    if v_rot.rows:
        v_rot.report(r)
    secure_round_summary(r, [v_rk, v_rot])

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
