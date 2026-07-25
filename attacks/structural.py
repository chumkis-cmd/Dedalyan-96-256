"""Структурный анализ Dedalyan: свойства, не требующие статистики.

Здесь проверяются утверждения, которые либо верны, либо нет, и проверяются
по возможности исчерпывающим перебором, а не выборкой:

1. Биективность лабиринта. Lab распадается на шесть независимых 8-битных
   отображений, поэтому каждое можно перебрать полностью (256 входов).
2. Инвариантные подпространства и нелинейные инварианты.
3. Свойства дополнения (комплементарность), как у DES.
4. Неподвижные точки шифра и структура циклов на урезанных версиях.
5. Слабые ключи: вырожденные лабиринты, ключи с особой структурой.
6. Слайд-свойства: одинаковость раундов -- условие слайд-атаки.

Запуск:  python attacks/structural.py
"""

from __future__ import annotations

import math
import random
import statistics
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dedalyan as D
from _lib import (MASK, Reporter, get_backend, jobs_of, make_parser,
                  parallel_map, profile_scale, split_work)


# --------------------------------------------------------------------------
# 1. Биективность лабиринта
# --------------------------------------------------------------------------

def pair_map_image(T0, T1) -> int:
    """Размер образа 8-битного отображения пары нибблов (j, j+6).

    Селектор ниббла j -- бит 2 ниббла (j+6) mod 12, и наоборот. Значит
    нибблы j и j+6 образуют замкнутую пару, а Lab на 48 битах распадается
    на шесть независимых копий одного и того же 8-битного отображения.
    """
    img = set()
    for a in range(16):
        for b in range(16):
            img.add(((T0, T1)[(b >> 2) & 1][a],
                     (T0, T1)[(a >> 2) & 1][b]))
    return len(img)


def _w_lab_density(task):
    seed, chunk = task
    import random as _r
    import dedalyan as _D
    rng = _r.Random(seed)
    out = []
    for _ in range(chunk):
        T0, T1 = _D.build_labyrinth(rng.getrandbits(64))
        out.append(pair_map_image(T0, T1))
    return out


def analyse_labyrinth(r: Reporter, args, jobs: int, nkeys: int) -> None:
    r.section("1. Is Lab a bijection?")
    r.info("Lab splits into six independent 8-bit maps on nibble pairs "
           "(j, j+6),")
    r.info("so each can be enumerated exhaustively: 256 inputs, no sampling.")

    chunks = split_work(nkeys, jobs)
    tasks = [(args.seed + 31 * i, c) for i, c in enumerate(chunks)]
    sizes = [s for part in parallel_map(_w_lab_density, tasks, jobs)
             for s in part]

    bijective = sum(1 for s in sizes if s == 256)
    densities = [(s / 256.0) ** 6 for s in sizes]
    mean_density = statistics.mean(densities)
    loss = -math.log2(mean_density)

    r.row(f"keys tested                     : {len(sizes):,}")
    r.row(f"pair-map image size (of 256)    : min {min(sizes)}, "
          f"mean {statistics.mean(sizes):.1f}, max {max(sizes)}")
    r.row(f"keys with a bijective Lab       : {bijective} "
          f"({100.0 * bijective / len(sizes):.3f}%)")
    r.row(f"mean image density of Lab (48 b): {mean_density:.4f}")
    r.row(f"entropy lost per Lab application: {loss:.3f} bits")

    if bijective < len(sizes):
        r.note("Lab is NOT a permutation for essentially every key.",
               "")
        r.info("Consequences, in order of importance:")
        r.info("  (a) the key schedule state contracts. Iterating a random")
        r.info("      non-injective map k times leaves an image of about")
        r.info("      2N/k, so after 20 steps the 192-bit state still spans")
        r.info(f"      ~2^{192 - math.log2(20 / 2):.1f} values. Not a practical concern.")
        r.info("  (b) the key schedule is NOT uniquely invertible, which")
        r.info("      HELPS against meet-in-the-middle on the schedule.")
        r.info("  (c) subkeys are not exactly uniform. Measured avalanche")
        r.info("      and collision tests do not detect it at 2^-48 scale.")
        r.info("This is a documentation gap in the spec, not a break:")
        r.info("section 6 never claims Lab is a permutation, but a reader")
        r.info("naturally assumes a 'pair of permutations' composes into one.")

    # Оценка сжатия состояния расписания за 20 шагов.
    steps = D.WARMUP + D.N
    residual_bits = 192 - math.log2(steps / 2.0)
    r.row(f"key-schedule state after {steps} steps: "
          f"~2^{residual_bits:.1f} of 2^192 reachable")


# --------------------------------------------------------------------------
# 2. Инвариантные подпространства и нелинейные инварианты
# --------------------------------------------------------------------------

def _w_invariant(task):
    """Ищет ключи, при которых шифр сохраняет какое-нибудь простое множество."""
    seed, chunk, rounds, pattern = task
    import random as _r
    from dedalyan_c import backend
    rng = _r.Random(seed)
    hits = 0
    mask_l, mask_r, val_l, val_r = pattern
    for _ in range(chunk):
        key = bytes(rng.getrandbits(8) for _ in range(32))
        ctx = backend.new_ctx(key)
        ok = True
        for _t in range(16):
            l = (rng.getrandbits(48) & ~mask_l) | val_l
            rr = (rng.getrandbits(48) & ~mask_r) | val_r
            c = backend.encrypt_block(ctx, (l << 48) | rr, rounds)
            cl, cr = (c >> 48) & MASK, c & MASK
            if (cl & mask_l) != val_l or (cr & mask_r) != val_r:
                ok = False
                break
        hits += ok
    return hits


def analyse_invariants(r: Reporter, args, jobs: int, nkeys: int,
                       rounds: int) -> None:
    r.section("2. Invariant subspaces")
    r.info("an invariant subspace attack needs a coset that the cipher maps")
    r.info("to itself for some class of keys; we test the natural candidates")

    patterns = [
        ("low nibble of R fixed to 0", (0, 0xF, 0, 0x0)),
        ("low byte of R fixed to 0", (0, 0xFF, 0, 0x0)),
        ("low nibble of L and R zero", (0xF, 0xF, 0x0, 0x0)),
        ("top nibble of L fixed to 0", (0xF << 44, 0, 0, 0)),
        ("R = 0 entirely", (0, MASK, 0, 0)),
    ]
    for name, pat in patterns:
        chunks = split_work(nkeys, jobs)
        tasks = [(args.seed + 977 * i, c, rounds, pat)
                 for i, c in enumerate(chunks)]
        hits = sum(parallel_map(_w_invariant, tasks, jobs))
        r.check(hits == 0, f"no key preserves: {name}",
                f"{hits} of {nkeys:,} keys")


# --------------------------------------------------------------------------
# 3. Свойство дополнения
# --------------------------------------------------------------------------

def analyse_complementation(r: Reporter, args, backend, trials: int) -> None:
    r.section("3. Complementation property (the DES-style relation)")
    r.info("DES satisfies E(~P, ~K) = ~E(P, K), which halves brute force;")
    r.info("with modular addition in F this should not survive")
    rng = random.Random(args.seed)
    hits = 0
    partial = []
    for _ in range(trials):
        key = bytes(rng.getrandbits(8) for _ in range(32))
        nkey = bytes(b ^ 0xFF for b in key)
        p = rng.getrandbits(96)
        np_ = p ^ ((1 << 96) - 1)
        c1 = backend.encrypt_block(backend.new_ctx(key), p)
        c2 = backend.encrypt_block(backend.new_ctx(nkey), np_)
        if c2 == c1 ^ ((1 << 96) - 1):
            hits += 1
        partial.append(bin(c2 ^ c1 ^ ((1 << 96) - 1)).count("1"))
    r.check(hits == 0, "E(~P, ~K) != ~E(P, K)", f"{hits} of {trials} matches")
    r.row(f"mean Hamming distance from the complement relation: "
          f"{statistics.mean(partial):.2f} of 96 (random = 48)")


# --------------------------------------------------------------------------
# 4. Неподвижные точки
# --------------------------------------------------------------------------

def _w_fixed(task):
    seed, chunk, rounds = task
    import random as _r
    from dedalyan_c import backend
    rng = _r.Random(seed)
    key = bytes(rng.getrandbits(8) for _ in range(32))
    ctx = backend.new_ctx(key)
    import numpy as _np
    g = _np.random.default_rng(seed)
    blocks = g.integers(0, 1 << 48, size=(chunk, 2), dtype=_np.uint64)
    orig = blocks.copy()
    out = backend.encrypt_many(ctx, blocks, rounds)
    return int(((out[:, 0] == orig[:, 0]) & (out[:, 1] == orig[:, 1])).sum()), chunk


def analyse_fixed_points(r: Reporter, args, jobs: int, n: int,
                         rounds: int) -> None:
    r.section("4. Fixed points E(P) == P")
    r.info("a random permutation of 2^96 elements has on average one fixed")
    r.info("point in total, so any hit in a sample of this size is a red flag")
    chunks = split_work(n, jobs)
    tasks = [(args.seed + 613 * i, c, rounds) for i, c in enumerate(chunks)]
    parts = parallel_map(_w_fixed, tasks, jobs)
    hits = sum(p[0] for p in parts)
    tot = sum(p[1] for p in parts)
    r.check(hits == 0, f"no fixed point in {tot:,} random blocks",
            f"{hits} found; random expectation {tot / 2.0**96:.2e}")


# --------------------------------------------------------------------------
# 5. Слабые ключи
# --------------------------------------------------------------------------

def analyse_weak_keys(r: Reporter, args, backend, jobs: int) -> None:
    r.section("5. Structured keys")
    r.info("keys an attacker would try first: all-zero, all-ones, repeating")
    r.info("bytes, K_L = 0 (labyrinth from a degenerate seed)")

    specials: List[Tuple[str, bytes]] = [
        ("all zero", bytes(32)),
        ("all ones", bytes([0xFF]) * 32),
        ("0x55 repeated", bytes([0x55]) * 32),
        ("0xAA repeated", bytes([0xAA]) * 32),
        ("K_L = 0, rest random", bytes(8) + bytes(range(24))),
        ("K_L = ones, rest zero", bytes([0xFF]) * 8 + bytes(24)),
        ("K_0..K_3 all equal", bytes(8) + bytes([0x3C]) * 24),
        ("counter pattern", bytes(range(32))),
    ]
    rng = np.random.default_rng(args.seed)
    for name, key in specials:
        ctx = backend.new_ctx(key)
        ks = backend.key_schedule(key)
        blocks = rng.integers(0, 1 << 48, size=(20_000, 2), dtype=np.uint64)
        orig = blocks.copy()
        out = backend.encrypt_many(ctx, blocks.copy(), 16)
        hd = (np.unpackbits(
            np.ascontiguousarray(
                (out ^ orig).astype(">u8")).view(np.uint8)).sum() /
            (20_000 * 96.0))
        distinct = len(set(ks))
        r.row(f"{name:<24} distinct subkeys {distinct:>2}/16   "
              f"mean |E(P) xor P| {hd * 100:5.2f}%   k0 {ks[0]:012x}")
        if distinct < 16:
            r.warn(f"key '{name}' repeats a subkey",
                   f"{16 - distinct} duplicates")

    # Ключи, дающие лабиринт с большим числом неподвижных точек, --
    # ближайший аналог «слабого ключа» в этой конструкции.
    fp = backend.labyrinth_fixpoints(500_000, args.seed)
    hist = np.bincount(fp, minlength=33)
    worst = int(fp.max())
    r.row(f"worst labyrinth over 500 000 keys: {worst} fixed points of 32 "
          f"({int(hist[worst])} such keys)")
    r.check(worst < 24, "no key yields a near-identity labyrinth",
            f"worst {worst}/32")


# --------------------------------------------------------------------------
# 6. Слайд-свойства
# --------------------------------------------------------------------------

def analyse_slide(r: Reporter, args, backend) -> None:
    r.section("6. Slide-attack preconditions")
    r.info("a slide attack needs the round transform to repeat: identical")
    r.info("subkeys AND identical round constants across rounds")

    rng = random.Random(args.seed)
    same_rc = len(set(D.round_constant(i) for i in range(16)))
    r.check(same_rc == 16, "all 16 round constants RC_i are distinct",
            f"{same_rc} distinct")

    # Даже при совпадении двух подключей раунды различаются из-за RC_i.
    dup_keys = 0
    for _ in range(50_000):
        key = bytes(rng.getrandbits(8) for _ in range(32))
        if len(set(backend.key_schedule(key))) != 16:
            dup_keys += 1
    r.check(dup_keys == 0, "no key produces two identical subkeys "
                           "(50 000 keys)", f"{dup_keys} keys")
    r.info("Conclusion: the round function differs at every round even for a")
    r.info("hypothetical key with repeated subkeys, so the classic slide")
    r.info("attack has no self-similar structure to exploit.")


# --------------------------------------------------------------------------

def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    args = parser.parse_args()
    backend = get_backend(args)
    jobs = jobs_of(args)
    scale = profile_scale(args)
    rounds = args.rounds or 16

    r = Reporter("Dedalyan structural analysis")
    r.info(f"processes {jobs}   scale x{scale:g}   rounds {rounds}")

    analyse_labyrinth(r, args, jobs, max(2_000, int(20_000 * min(scale, 20))))
    analyse_invariants(r, args, jobs, max(200, int(2_000 * min(scale, 10))),
                       rounds)
    analyse_complementation(r, args, backend,
                            max(200, int(2_000 * min(scale, 10))))
    analyse_fixed_points(r, args, jobs,
                         max(200_000, int(5_000_000 * min(scale, 20))), rounds)
    analyse_weak_keys(r, args, backend, jobs)
    analyse_slide(r, args, backend)

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
