"""Невозможные дифференциалы Dedalyan.

Обычный дифференциальный криптоанализ ищет разности, встречающиеся ЧАЩЕ
ожидаемого. Невозможный ищет обратное: разности, которые не встречаются
НИКОГДА. Такой различитель не требует статистического преимущества -- одна
пара, попавшая в «невозможную» разность, отбраковывает ключ целиком.

Проверяются три уровня:

1. Побитовый: при входной разности Δ существуют ли выходные биты, которые
   никогда не переворачиваются (или переворачиваются всегда). Для раундов
   1-3 такие биты обязаны быть -- это геометрия Фейстеля.
2. Понибблевый (усечённые невозможные дифференциалы): для каждой из 24 позиций
   нибблов -- какие из 16 значений разности ни разу не наблюдались. Значение,
   ожидаемое N/16 раз и не встретившееся ни разу, невозможно с уверенностью
   e^(-N/16).
3. Miss-in-the-middle: разность прогоняется вперёд r1 раундов и назад r2
   раундов, и проверяется, могут ли они встретиться в середине. Это даёт
   доказательные, а не статистические невозможные дифференциалы.

Запуск:  python attacks/impossible.py
         python attacks/impossible.py --profile deep --max-rounds 8
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
                  jobs_of, make_parser, parallel_map, profile_scale,
                  secure_round_summary, single_bit_differences, split_work)

BASE_SAMPLES = 500_000


def _w_nibble(task):
    key, rounds, diffs, n, seed = task
    from dedalyan_c import backend
    import numpy as _np
    ctx = backend.new_ctx(key)
    out = _np.zeros((len(diffs), 24, 16), dtype=bool)
    for i, (dl, dr) in enumerate(diffs):
        out[i] = backend.diff_nibble_seen(ctx, rounds, dl, dr, n,
                                          seed + 104729 * i).astype(bool)
    return out


def _w_bitwise(task):
    key, rounds, diffs, n, seed = task
    from dedalyan_c import backend
    import numpy as _np
    ctx = backend.new_ctx(key)
    out = _np.zeros((len(diffs), 96), dtype=_np.float64)
    for i, (dl, dr) in enumerate(diffs):
        out[i] = backend.diff_bitcount(ctx, rounds, dl, dr, n,
                                       seed + 7919 * i).astype(_np.float64) / n
    return out


def _w_middle(task):
    """Miss-in-the-middle: множества достижимых усечённых разностей.

    Вперёд из Δin за r1 раундов и назад из Δout за r2 раундов. Если множества
    не пересекаются ни по одной позиции ниббла, дифференциал невозможен.
    """
    key, r1, r2, din, dout, n, seed = task
    import numpy as _np
    from dedalyan_c import backend
    ctx = backend.new_ctx(key)
    g = _np.random.default_rng(seed)

    fwd = _np.zeros((24, 16), dtype=bool)
    bwd = _np.zeros((24, 16), dtype=bool)
    batch = 50_000
    done = 0
    while done < n:
        m = min(batch, n - done)
        p = g.integers(0, 1 << 48, size=(m, 2), dtype=_np.uint64)
        q = p.copy()
        q[:, 0] ^= _np.uint64(din[0])
        q[:, 1] ^= _np.uint64(din[1])
        a = backend.encrypt_many(ctx, p, r1)
        b = backend.encrypt_many(ctx, q, r1)
        for arr, acc in ((a[:, 0] ^ b[:, 0], 12), (a[:, 1] ^ b[:, 1], 0)):
            for j in range(12):
                vals = _np.unique(((arr >> _np.uint64(4 * j)) &
                                   _np.uint64(0xF)).astype(_np.int64))
                fwd[acc + j, vals] = True

        c = g.integers(0, 1 << 48, size=(m, 2), dtype=_np.uint64)
        d = c.copy()
        d[:, 0] ^= _np.uint64(dout[0])
        d[:, 1] ^= _np.uint64(dout[1])
        a = backend.decrypt_many(ctx, c, r2)
        b = backend.decrypt_many(ctx, d, r2)
        for arr, acc in ((a[:, 0] ^ b[:, 0], 12), (a[:, 1] ^ b[:, 1], 0)):
            for j in range(12):
                vals = _np.unique(((arr >> _np.uint64(4 * j)) &
                                   _np.uint64(0xF)).astype(_np.int64))
                bwd[acc + j, vals] = True
        done += m
    return fwd, bwd


def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    parser.add_argument("--max-rounds", type=int, default=7)
    args = parser.parse_args()

    backend = get_backend(args)
    jobs = jobs_of(args)
    scale = profile_scale(args)
    rng = random.Random(args.seed)
    key = bytes(rng.getrandbits(8) for _ in range(32))

    n = max(50_000, int(BASE_SAMPLES * scale))

    r = Reporter("Dedalyan impossible differentials")
    r.info(f"key {key[:8].hex()}...   pairs per difference {n:,}   "
           f"processes {jobs}")
    r.info(f"a nibble value expected {n / 16:,.0f} times and never seen is "
           f"impossible with confidence 1 - e^-{n / 16:,.0f}")

    v_bit = RoundVerdict("deterministic output bit")
    v_nib = RoundVerdict("impossible truncated differential")

    singles = single_bit_differences()
    probe = singles[:8] + singles[48:56]      # по 8 бит из каждой половины

    # ---- 1. Побитовые детерминированные соотношения ----------------------
    r.section("1. Deterministic output bits (bitwise impossible differences)")
    r.info("an output bit that NEVER flips (p = 0) or ALWAYS flips (p = 1)")
    r.info("under a fixed input difference is a probability-1 relation")
    r.row(f"{'rounds':>7}  {'always 0':>9}  {'always 1':>9}  "
          f"{'of 96 x #diffs':>15}")
    for rounds in range(1, args.max_rounds + 1):
        per = max(1, len(probe) // jobs)
        tasks = [(key, rounds, probe[i:i + per], n, args.seed + 3 * rounds + i)
                 for i in range(0, len(probe), per)]
        probs = np.concatenate(parallel_map(_w_bitwise, tasks, jobs), axis=0)
        never = int((probs == 0.0).sum())
        always = int((probs == 1.0).sum())
        total = probs.size
        r.row(f"{rounds:>7}  {never:>9}  {always:>9}  {total:>15}")
        v_bit.add(rounds, float(never + always), 0.5,
                  f"{never + always} deterministic bits")
        if never + always == 0 and rounds >= 5:
            break

    # ---- 2. Усечённые невозможные дифференциалы --------------------------
    r.section("2. Truncated (nibble) impossible differentials")
    r.info("for each of 24 nibble positions: which of the 16 difference")
    r.info("values never appear")
    r.row(f"{'rounds':>7}  {'missing':>9}  {'of':>7}  {'expected by chance':>20}")
    for rounds in range(1, args.max_rounds + 1):
        per = max(1, len(probe) // jobs)
        tasks = [(key, rounds, probe[i:i + per], n, args.seed + 5 * rounds + i)
                 for i in range(0, len(probe), per)]
        seen = np.concatenate(parallel_map(_w_nibble, tasks, jobs), axis=0)
        missing = int((~seen).sum())
        total = seen.size
        exp = total * math.exp(-n / 16.0)
        r.row(f"{rounds:>7}  {missing:>9}  {total:>7}  {exp:>20.2e}")
        v_nib.add(rounds, float(missing), max(exp, 0.5),
                  f"{missing} missing nibble values")
        if missing == 0 and rounds >= 5:
            break

    # ---- 3. Miss-in-the-middle -------------------------------------------
    r.section("3. Miss-in-the-middle")
    r.info("propagate forward r1 rounds and backward r2 rounds; if the two")
    r.info("reachable sets are disjoint at some nibble, the (r1+r2)-round")
    r.info("differential is impossible")
    nmid = max(50_000, int(200_000 * min(scale, 10)))
    din = (0, 1)
    dout = (0, 1)
    r.row(f"{'r1':>3}  {'r2':>3}  {'total':>6}  {'disjoint nibble positions':>26}")
    for r1 in range(1, 5):
        for r2 in range(1, 5):
            chunks = split_work(nmid, jobs)
            tasks = [(key, r1, r2, din, dout, c, args.seed + 71 * r1 + r2 + i)
                     for i, c in enumerate(chunks)]
            parts = parallel_map(_w_middle, tasks, jobs)
            fwd = parts[0][0].copy()
            bwd = parts[0][1].copy()
            for f, b in parts[1:]:
                fwd |= f
                bwd |= b
            disjoint = int((~(fwd & bwd)).all(axis=1).sum())
            r.row(f"{r1:>3}  {r2:>3}  {r1 + r2:>6}  {disjoint:>26}")

    v_bit.report(r)
    v_nib.report(r)
    secure_round_summary(r, [v_bit, v_nib])

    r.section("Interpretation")
    r.info("Deterministic relations through round 3 are unavoidable in any")
    r.info("Feistel network: after r rounds one output half equals a known")
    r.info("function of the inputs. An impossible differential is only")
    r.info("interesting if it survives past full diffusion (round 4 here).")
    r.info("Key recovery on top of an r-round impossible differential")
    r.info("typically covers r + 3 to r + 4 rounds.")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
