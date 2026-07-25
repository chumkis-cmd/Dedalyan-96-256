"""Полнота диффузии: матрица зависимостей вход -> выход по раундам.

Для каждого входного бита b и выходного бита o проверяется, встречается ли
хотя бы одна пара текстов, у которой переворот b меняет o. Раунд полного
покрытия -- первый, на котором зависят все 96 x 96 пар.

Спецификация (раздел 9): полное покрытие с раунда 4, доля покрытия по раундам
26.0% -> 75.5% -> 99.97% -> 100%.

Запуск:  python tests/test_diffusion.py
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dedalyan_harness import (Reporter, get_backend, jobs_of, make_parser,
                              parallel_map, split_work)

SPEC_COVERAGE = {1: 26.0, 2: 75.5, 3: 99.97, 4: 100.0}
SPEC_FULL_ROUND = 4
DEFAULT_SAMPLES = 4000


def _worker(task):
    seed, chunk, rounds, key = task
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    return backend.diffusion_cover(ctx, rounds, chunk, seed)


def coverage(backend, key: bytes, rounds: int, n: int, seed: int, jobs: int):
    """Возвращает булеву матрицу 96x96: зависит ли выходной бит от входного."""
    chunks = split_work(n, jobs)
    tasks = [(seed + 7919 * i, c, rounds, key) for i, c in enumerate(chunks)]
    parts = parallel_map(_worker, tasks, jobs)
    acc = parts[0].copy()
    for p in parts[1:]:
        acc |= p
    # acc[b] = (l, r) -- ИЛИ всех разностей при перевороте входного бита b.
    bits = np.zeros((96, 96), dtype=bool)
    for b in range(96):
        l, rr = int(acc[b][0]), int(acc[b][1])
        word = (l << 48) | rr
        for o in range(96):
            bits[b, o] = (word >> o) & 1
    return bits


def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    args = parser.parse_args()
    backend = get_backend(args)
    jobs = jobs_of(args)
    n = args.samples or DEFAULT_SAMPLES
    rng = random.Random(args.seed)

    r = Reporter("Dedalyan diffusion -- input-bit to output-bit dependency")
    key = bytes(rng.getrandbits(8) for _ in range(32))
    r.info(f"samples per round: {n:,}   processes: {jobs}   "
           f"key: {key[:8].hex()}...")
    r.info("a pair (b, o) counts as covered if flipping input bit b ever "
           "flips output bit o")

    r.section("Coverage by round")
    r.row(f"{'round':>5}  {'covered':>10}  {'of 9216':>8}  {'spec':>8}")

    full_round = None
    cov_pct = {}
    for rounds in range(1, 9):
        bits = coverage(backend, key, rounds, n, args.seed + rounds, jobs)
        c = int(bits.sum())
        pct = 100.0 * c / 9216
        cov_pct[rounds] = pct
        spec = SPEC_COVERAGE.get(rounds)
        r.row(f"{rounds:>5}  {pct:9.2f}%  {c:>8}  "
              f"{('%7.2f%%' % spec) if spec is not None else '       -'}")
        if full_round is None and c == 9216:
            full_round = rounds
        if full_round is not None and rounds >= full_round + 1:
            break

    r.section("Verdict")
    r.check(full_round is not None, "full diffusion is reached at all")
    if full_round is not None:
        r.check(full_round == SPEC_FULL_ROUND,
                f"full coverage at round {SPEC_FULL_ROUND} (spec section 9)",
                f"measured round {full_round}")
        r.info(f"margin: {16 - full_round} of 16 rounds beyond full diffusion")

    for rounds, spec in sorted(SPEC_COVERAGE.items()):
        if rounds not in cov_pct:
            continue
        got = cov_pct[rounds]
        # Раунды 1-2 -- структурные, они воспроизводятся точно.
        tol = 2.0 if rounds <= 2 else 0.5
        r.check(abs(got - spec) <= tol,
                f"round {rounds} coverage within {tol}pp of {spec}%",
                f"got {got:.2f}%")

    r.section("Structural checks on round 1 (Feistel geometry)")
    bits1 = coverage(backend, key, 1, n, args.seed + 1, jobs)
    # После одного раунда: L_out = R, R_out = L ^ F(R).
    # Переворот бита L (входные биты 48..95) обязан менять ровно один бит.
    upper_rows = bits1[48:96].sum(axis=1)
    r.check(bool((upper_rows == 1).all()),
            "flipping an L bit affects exactly 1 output bit after round 1",
            f"counts {sorted(set(upper_rows.tolist()))}")
    # Переворот бита R обязан менять хотя бы бит L_out.
    lower_rows = bits1[0:48].sum(axis=1)
    r.check(bool((lower_rows > 1).all()),
            "flipping an R bit affects more than 1 output bit after round 1",
            f"min {int(lower_rows.min())}, max {int(lower_rows.max())}")

    r.section("Per-bit weakest link at the full-diffusion round")
    if full_round:
        bits = coverage(backend, key, full_round, n, args.seed + 99, jobs)
        in_deg = bits.sum(axis=1)
        out_deg = bits.sum(axis=0)
        r.info(f"input bit fan-out : min {int(in_deg.min())}, "
               f"max {int(in_deg.max())} of 96")
        r.info(f"output bit fan-in : min {int(out_deg.min())}, "
               f"max {int(out_deg.max())} of 96")
        r.check(int(in_deg.min()) == 96 and int(out_deg.min()) == 96,
                "no weak bit remains at the full-diffusion round")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
