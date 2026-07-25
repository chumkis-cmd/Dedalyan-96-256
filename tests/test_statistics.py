"""Статистика гаммы в режиме счётчика (раздел 10.2).

Шифр в режиме CTR обязан быть неотличим от случайного потока. Проверяются:
монобитный тест, хи-квадрат по байтам, частоты внутри блока, серии (runs),
покер-тест на нибблах и приблизительная энтропия. Минимум пять разных ключей,
как требует спецификация.

Спецификация (раздел 9): монобит 0.4997-0.5002, хи-квадрат по байтам 233-281
при критическом значении 293 (df = 255, alpha = 0.05).

Запуск:  python tests/test_statistics.py
         python tests/test_statistics.py --profile deep
"""

from __future__ import annotations

import math
import random
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dedalyan_harness import (Reporter, chi2_sf, get_backend, jobs_of,
                              make_parser, parallel_map)

CHI2_CRIT_255 = 293.25          # alpha = 0.05, df = 255
SPEC_MONOBIT = (0.4997, 0.5002)
SPEC_CHI2 = (233.0, 281.0)
NKEYS = 5
DEFAULT_MIB = 8


def _worker(task):
    """Считает статистики по куску гаммы, не удерживая её целиком."""
    key, rounds, ctr_hi, ctr_lo, nbytes = task
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    data = np.frombuffer(backend.ctr_stream(ctx, rounds, ctr_hi, ctr_lo,
                                            nbytes), dtype=np.uint8)
    bytehist = np.bincount(data, minlength=256).astype(np.int64)
    bits = np.unpackbits(data)
    ones = int(bits.sum())
    # Серии: число смен значения соседних бит.
    runs = int((bits[1:] != bits[:-1]).sum()) + 1
    # Покер-тест на нибблах.
    nib = np.concatenate([data >> 4, data & 0xF])
    nibhist = np.bincount(nib, minlength=16).astype(np.int64)
    return bytehist, ones, len(bits), runs, nibhist


def monobit_p(ones: int, nbits: int) -> float:
    s = abs(2.0 * ones - nbits) / math.sqrt(nbits)
    return math.erfc(s / math.sqrt(2.0))


def runs_p(runs: int, ones: int, nbits: int) -> float:
    """NIST STS Runs Test."""
    pi = ones / nbits
    if abs(pi - 0.5) >= 2.0 / math.sqrt(nbits):
        return 0.0
    num = abs(runs - 2.0 * nbits * pi * (1 - pi))
    den = 2.0 * math.sqrt(2.0 * nbits) * pi * (1 - pi)
    return math.erfc(num / den)


def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    parser.add_argument("--mib", type=int, default=None,
                        help="megabytes of keystream per key")
    args = parser.parse_args()
    backend = get_backend(args)
    jobs = jobs_of(args)
    rounds = args.rounds or 16
    rng = random.Random(args.seed)

    mib = args.mib or {"quick": 2, "standard": DEFAULT_MIB,
                       "deep": 64, "overnight": 512}[args.profile]
    per_key = mib * 1024 * 1024

    r = Reporter(f"Dedalyan statistics -- CTR keystream, {NKEYS} keys x {mib} MiB")
    r.info(f"rounds: {rounds}   processes: {jobs}")
    r.info(f"chi-square critical value (df=255, a=0.05): {CHI2_CRIT_255}")

    all_monobit = []
    all_chi2 = []
    r.section("Per-key results")
    r.row(f"{'key':>4}  {'monobit':>9}  {'p(mono)':>9}  {'chi2/255':>9}  "
          f"{'p(chi2)':>9}  {'p(runs)':>9}  {'poker':>9}")

    for ki in range(NKEYS):
        key = bytes(rng.getrandbits(8) for _ in range(32))
        # Каждый процесс берёт свой диапазон счётчика: потоки не пересекаются.
        chunk = per_key // jobs
        tasks = [(key, rounds, 0, (i * chunk) // 12, chunk) for i in range(jobs)]
        parts = parallel_map(_worker, tasks, jobs)

        bytehist = sum(p[0] for p in parts)
        ones = sum(p[1] for p in parts)
        nbits = sum(p[2] for p in parts)
        runs = sum(p[3] for p in parts)
        nibhist = sum(p[4] for p in parts)

        nbytes = int(bytehist.sum())
        exp = nbytes / 256.0
        chi2 = float(((bytehist - exp) ** 2 / exp).sum())
        p_chi = chi2_sf(chi2, 255)

        frac = ones / nbits
        p_mono = monobit_p(ones, nbits)
        p_runs = runs_p(runs, ones, nbits)

        nexp = nibhist.sum() / 16.0
        poker = float(((nibhist - nexp) ** 2 / nexp).sum())
        p_poker = chi2_sf(poker, 15)

        all_monobit.append(frac)
        all_chi2.append(chi2)
        r.row(f"{ki:>4}  {frac:9.6f}  {p_mono:9.4f}  {chi2:9.2f}  "
              f"{p_chi:9.4f}  {p_runs:9.4f}  {p_poker:9.4f}")

    r.section("Verdicts")
    lo, hi = min(all_monobit), max(all_monobit)
    r.check(SPEC_MONOBIT[0] - 0.0005 <= lo and hi <= SPEC_MONOBIT[1] + 0.0005,
            f"monobit in spec range {SPEC_MONOBIT}",
            f"observed {lo:.6f}..{hi:.6f}")
    # Строгий критерий: отклонение доли единиц от 1/2 в сигмах.
    nbits_total = per_key * 8
    sigma = 0.5 / math.sqrt(nbits_total)
    worst = max(abs(f - 0.5) for f in all_monobit) / sigma
    r.check(worst < 4.0, "monobit within 4 sigma for every key",
            f"worst {worst:.2f} sigma")

    r.check(all(c < CHI2_CRIT_255 for c in all_chi2),
            f"byte chi-square below critical {CHI2_CRIT_255}",
            f"observed {min(all_chi2):.1f}..{max(all_chi2):.1f} "
            f"(spec range {SPEC_CHI2[0]}-{SPEC_CHI2[1]})")

    # ---- дополнительные проверки -----------------------------------------
    r.section("Block-level structure")
    key = bytes(rng.getrandbits(8) for _ in range(32))
    ctx = backend.new_ctx(key)

    # Счётчик со всеми нулями и соседние значения не должны давать
    # коррелирующих блоков: это классическая слабость слабой диффузии.
    blocks = np.frombuffer(backend.ctr_stream(ctx, rounds, 0, 0, 12 * 200_000),
                           dtype=np.uint8).reshape(-1, 12)
    consecutive_hd = np.unpackbits(blocks[1:] ^ blocks[:-1], axis=1).sum(axis=1)
    mean_hd = float(consecutive_hd.mean())
    r.info(f"mean Hamming distance between consecutive CTR blocks: "
           f"{mean_hd:.3f} of 96")
    r.check(abs(mean_hd - 48.0) < 0.5, "consecutive blocks look independent",
            f"{mean_hd:.3f}")

    # Повторов блоков быть не должно (порог дней рождения -- 2^48).
    packed = [bytes(b) for b in blocks]
    r.check(len(set(packed)) == len(packed), "no repeated keystream block",
            f"{len(packed) - len(set(packed))} repeats in {len(packed):,}")

    # ECB на случайных входах: шифр как случайная перестановка.
    r.section("Random-input ECB")
    out = backend.random_ecb(ctx, rounds, 500_000, args.seed)
    # Раскладываем каждое 48-битное слово на 6 байт (big-endian).
    shifts = np.arange(40, -8, -8, dtype=np.uint64)
    hi = ((out[:, 0:1] >> shifts) & np.uint64(0xFF)).astype(np.uint8)
    lo = ((out[:, 1:2] >> shifts) & np.uint64(0xFF)).astype(np.uint8)
    ecb_bytes = np.concatenate([hi, lo], axis=1).reshape(-1)
    hist = np.bincount(ecb_bytes, minlength=256).astype(np.int64)
    exp = hist.sum() / 256.0
    chi2 = float(((hist - exp) ** 2 / exp).sum())
    r.check(chi2 < CHI2_CRIT_255, "ECB output byte chi-square below critical",
            f"{chi2:.2f}, p = {chi2_sf(chi2, 255):.4f}")

    r.section("Round-reduced sanity (should FAIL at very low round counts)")
    # Обратная проверка: тест обязан ловить слабый шифр. При 1 раунде
    # гамма в режиме счётчика заведомо неслучайна.
    weak = np.frombuffer(backend.ctr_stream(ctx, 1, 0, 0, 1 << 20),
                         dtype=np.uint8)
    wh = np.bincount(weak, minlength=256).astype(np.int64)
    we = wh.sum() / 256.0
    wchi = float(((wh - we) ** 2 / we).sum())
    r.check(wchi > CHI2_CRIT_255,
            "1-round keystream IS detected as non-random",
            f"chi2 = {wchi:.1f} (test has power)")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
