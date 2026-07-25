"""Лавинный эффект по открытому тексту, раунды 1..16 (раздел 10.2).

Измеряется доля перевёрнутых бит шифротекста при перевороте одного случайного
бита открытого текста. Сравнение -- с таблицей раздела 9 спецификации.

Идеальные значения для 96-битного блока: среднее 50%, стандартное отклонение
доли 5.10% (= sqrt(96 * 0.25) / 96).

Запуск:  python tests/test_avalanche.py
         python tests/test_avalanche.py --profile deep
"""

from __future__ import annotations

import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dedalyan_harness import (Reporter, autoscale, get_backend, jobs_of,
                              make_parser, parallel_map, split_work)

BLOCK_BITS = 96
IDEAL_SIGMA = math.sqrt(BLOCK_BITS * 0.25) / BLOCK_BITS   # 0.0510

# Раздел 9: (среднее %, ст. откл. %)
SPEC_TABLE = {
    1: (14.08, 12.95),
    2: (38.45, 12.85),
    3: (49.95, 5.19),
    4: (49.94, 5.13),
    8: (50.01, 5.16),
    16: (50.17, 5.12),
}

# Допуск на среднее в процентных пунктах: эти статистики устойчивы,
# но зависят от выборки ключей, поэтому берём с запасом.
MEAN_TOL_PP = 1.0
SIGMA_TOL_PP = 0.6


def _worker(task):
    """Возвращает (n, sum_hd, sum_hd2) для одного chunk."""
    seed, chunk, rounds, key = task
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    s1, s2 = backend.avalanche(ctx, rounds, chunk, seed)
    return chunk, s1, s2


def measure(backend, key: bytes, rounds: int, n: int, seed: int, jobs: int):
    """Среднее и ст. откл. доли перевёрнутых бит."""
    chunks = split_work(n, jobs)
    tasks = [(seed + 104729 * i, c, rounds, key) for i, c in enumerate(chunks)]
    res = parallel_map(_worker, tasks, jobs)
    total = sum(c for c, _, _ in res)
    s1 = sum(a for _, a, _ in res)
    s2 = sum(b for _, _, b in res)
    mean_hd = s1 / total
    var_hd = max(0.0, s2 / total - mean_hd * mean_hd)
    return mean_hd / BLOCK_BITS, math.sqrt(var_hd) / BLOCK_BITS, total


def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    args = parser.parse_args()
    backend = get_backend(args)
    jobs = jobs_of(args)
    rng = random.Random(args.seed)

    r = Reporter("Dedalyan avalanche -- plaintext bit flip, rounds 1..16")

    key = bytes(rng.getrandbits(8) for _ in range(32))
    ctx = backend.new_ctx(key)

    if args.samples:
        n = args.samples
    else:
        budget = (args.budget if args.budget is not None
                  else {"quick": 15.0, "standard": 120.0,
                        "deep": 1800.0, "overnight": 28800.0}[args.profile])
        # Бюджет делится на 16 раундов.
        n = autoscale(lambda k: backend.avalanche(ctx, 16, k, 1),
                      budget / 16.0 * jobs, verbose=args.verbose)
    r.info(f"samples per round: {n:,}   processes: {jobs}   key: {key[:8].hex()}...")
    r.info(f"ideal: mean 50.00%, sigma {IDEAL_SIGMA * 100:.2f}%")

    r.section("Measured avalanche by round")
    r.row(f"{'round':>5}  {'mean':>8}  {'sigma':>8}  {'spec mean':>10}  "
          f"{'spec sigma':>10}  verdict")

    results = {}
    for rounds in range(1, 17):
        mean, sigma, total = measure(backend, key, rounds, n,
                                     args.seed + rounds, jobs)
        results[rounds] = (mean, sigma)
        sm, ss = SPEC_TABLE.get(rounds, (None, None))
        verdict = ""
        if sm is not None:
            dm = abs(mean * 100 - sm)
            ds = abs(sigma * 100 - ss)
            verdict = "ok" if dm <= MEAN_TOL_PP and ds <= SIGMA_TOL_PP else "OFF"
        r.row(f"{rounds:>5}  {mean * 100:7.2f}%  {sigma * 100:7.2f}%  "
              f"{('%9.2f%%' % sm) if sm else '         -'}  "
              f"{('%9.2f%%' % ss) if ss else '         -'}  {verdict}")

    r.section("Comparison with spec section 9")
    for rounds, (sm, ss) in sorted(SPEC_TABLE.items()):
        mean, sigma = results[rounds]
        r.check(abs(mean * 100 - sm) <= MEAN_TOL_PP,
                f"round {rounds:2d} mean within {MEAN_TOL_PP}pp of {sm}%",
                f"got {mean * 100:.2f}%")
        r.check(abs(sigma * 100 - ss) <= SIGMA_TOL_PP,
                f"round {rounds:2d} sigma within {SIGMA_TOL_PP}pp of {ss}%",
                f"got {sigma * 100:.2f}%")

    r.section("Strict criteria (independent of the reference implementation)")
    # После полной диффузии среднее обязано быть 50% с точностью до шума.
    tol = 4.0 * IDEAL_SIGMA / math.sqrt(n)
    for rounds in (4, 8, 12, 16):
        mean, sigma = results[rounds]
        r.check(abs(mean - 0.5) <= max(tol, 0.002),
                f"round {rounds:2d} mean is 0.5 +- {max(tol, 0.002):.4f}",
                f"got {mean:.5f}")
    for rounds in (4, 8, 12, 16):
        _, sigma = results[rounds]
        r.check(abs(sigma - IDEAL_SIGMA) <= 0.004,
                f"round {rounds:2d} sigma matches binomial {IDEAL_SIGMA:.4f}",
                f"got {sigma:.5f}")

    # Лавина обязана расти монотонно на первых раундах и выйти на плато.
    r.check(results[1][0] < results[2][0] < results[3][0],
            "avalanche grows over rounds 1..3")
    r.check(all(abs(results[i][0] - 0.5) < 0.01 for i in range(4, 17)),
            "rounds 4..16 all within 1pp of 50%")

    r.section("Cross-key stability (5 independent keys, round 16)")
    means = []
    for i in range(5):
        k = bytes(rng.getrandbits(8) for _ in range(32))
        m, s, _ = measure(backend, k, 16, max(n // 5, 10_000),
                          args.seed + 1000 + i, jobs)
        means.append(m)
        r.row(f"key {i}: mean {m * 100:6.2f}%  sigma {s * 100:5.2f}%")
    spread = max(means) - min(means)
    r.check(spread < 0.01, "spread across keys below 1pp",
            f"{spread * 100:.3f}pp")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
