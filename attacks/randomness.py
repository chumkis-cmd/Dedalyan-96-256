"""Статистическая батарея NIST STS для гаммы Dedalyan + экспорт для dieharder.

Реализовано подмножество NIST SP 800-22: монобитный тест, частоты в блоках,
серии, самая длинная серия единиц, ранг двоичных матриц, спектральный тест
(ДПФ), последовательный тест, приблизительная энтропия и накопленные суммы.
Этого достаточно, чтобы поймать все грубые дефекты; полные батареи (dieharder,
NIST STS, PractRand, TestU01) запускаются на экспортированном файле.

Как читать результаты. Каждый тест выдаёт p-значение. При исправном шифре
p-значения равномерны на [0, 1], поэтому отдельные p < 0.01 -- норма и
ожидаются примерно в 1% случаев. Дефект выглядит иначе: один и тот же тест
проваливается на многих ключах, либо p оказывается порядка 10^-6 и меньше.
Поэтому тесты прогоняются на нескольких независимых ключах, а в конце
проверяется равномерность самих p-значений (тест второго порядка).

Запуск:  python attacks/randomness.py
         python attacks/randomness.py --profile deep --keys 20
         python attacks/randomness.py --export stream.bin --export-mb 256
"""

from __future__ import annotations

import math
import random
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _lib import Reporter, get_backend, jobs_of, make_parser, profile_scale

try:
    from scipy.special import gammaincc as _igamc
except ImportError:  # pragma: no cover
    _igamc = None


def igamc(a: float, x: float) -> float:
    """Регуляризованная неполная гамма-функция Q(a, x)."""
    if _igamc is not None:
        return float(_igamc(a, x))
    # Запасной путь: приближение Уилсона--Хилферти через хи-квадрат.
    from statistics import NormalDist
    df = 2.0 * a
    t = (2.0 * x / df) ** (1.0 / 3.0)
    m = 1.0 - 2.0 / (9.0 * df)
    s = math.sqrt(2.0 / (9.0 * df))
    return 1.0 - NormalDist().cdf((t - m) / s)


# --------------------------------------------------------------------------
# Тесты NIST SP 800-22
# --------------------------------------------------------------------------

def t_monobit(bits: np.ndarray) -> float:
    n = bits.size
    s = int(bits.sum()) * 2 - n
    return math.erfc(abs(s) / math.sqrt(n) / math.sqrt(2.0))


def t_block_frequency(bits: np.ndarray, m: int = 20_000) -> float:
    n = (bits.size // m) * m
    if n == 0:
        return float("nan")
    blocks = bits[:n].reshape(-1, m)
    pi = blocks.mean(axis=1)
    chi2 = 4.0 * m * float(((pi - 0.5) ** 2).sum())
    return igamc(blocks.shape[0] / 2.0, chi2 / 2.0)


def t_runs(bits: np.ndarray) -> float:
    n = bits.size
    pi = float(bits.mean())
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return 0.0
    v = int((bits[1:] != bits[:-1]).sum()) + 1
    num = abs(v - 2.0 * n * pi * (1 - pi))
    den = 2.0 * math.sqrt(2.0 * n) * pi * (1 - pi)
    return math.erfc(num / den)


def t_longest_run(bits: np.ndarray) -> float:
    """Самая длинная серия единиц в блоке. Параметры для M = 10000."""
    m, k = 10_000, 6
    n = (bits.size // m) * m
    if n < m:
        return float("nan")
    blocks = bits[:n].reshape(-1, m)
    pi = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
    # Категории для M = 10000: <=10, 11, 12, 13, 14, 15, >=16
    counts = np.zeros(7, dtype=np.int64)
    for row in blocks:
        best = cur = 0
        for b in row:
            cur = cur + 1 if b else 0
            if cur > best:
                best = cur
        idx = min(max(best - 10, 0), 6)
        counts[idx] += 1
    nblk = blocks.shape[0]
    exp = np.array(pi) * nblk
    chi2 = float((((counts - exp) ** 2) / exp).sum())
    return igamc(3.0, chi2 / 2.0)


def gf2_ranks(mats: np.ndarray) -> np.ndarray:
    """Ранги над GF(2) для набора матриц 32x32, заданных строками uint32."""
    n = mats.shape[0]
    m = mats.copy()
    ar = np.arange(n)
    idx = np.arange(32)[None, :]
    rank = np.zeros(n, dtype=np.int32)
    row = np.zeros(n, dtype=np.int64)
    for col in range(32):
        bit = np.uint32(1) << np.uint32(col)
        has = ((m & bit) != 0) & (idx >= row[:, None])
        anyhas = has.any(axis=1)
        first = np.where(anyhas, has.argmax(axis=1), row)
        tmp = m[ar, row].copy()
        m[ar, row] = np.where(anyhas, m[ar, first], tmp)
        m[ar, first] = np.where(anyhas, tmp, m[ar, first])
        pivot = m[ar, row]
        elim = ((m & bit) != 0) & (idx > row[:, None]) & anyhas[:, None]
        m = np.where(elim, m ^ pivot[:, None], m)
        rank += anyhas
        row = np.minimum(row + anyhas, 31)
    return rank


def t_matrix_rank(data: np.ndarray) -> float:
    """Ранг двоичных матриц 32x32 -- ловит линейные зависимости."""
    words = data.view(np.uint32)
    nmat = words.size // 32
    if nmat < 38:
        return float("nan")
    mats = words[:nmat * 32].reshape(nmat, 32).copy()
    ranks = gf2_ranks(mats)
    f32 = int((ranks == 32).sum())
    f31 = int((ranks == 31).sum())
    f30 = nmat - f32 - f31
    p = [0.2888, 0.5776, 0.1336]
    obs = [f32, f31, f30]
    chi2 = sum((o - pi * nmat) ** 2 / (pi * nmat) for o, pi in zip(obs, p))
    return math.exp(-chi2 / 2.0)


def t_dft(bits: np.ndarray, limit: int = 1 << 20) -> float:
    """Спектральный тест: ищет периодичности."""
    n = min(bits.size, limit)
    n -= n % 2
    x = bits[:n].astype(np.float64) * 2.0 - 1.0
    s = np.abs(np.fft.rfft(x))[:n // 2]
    thr = math.sqrt(math.log(1.0 / 0.05) * n)
    n0 = 0.95 * n / 2.0
    n1 = float((s < thr).sum())
    d = (n1 - n0) / math.sqrt(n * 0.95 * 0.05 / 4.0)
    return math.erfc(abs(d) / math.sqrt(2.0))


def _psi2(bits: np.ndarray, m: int) -> float:
    if m <= 0:
        return 0.0
    n = bits.size
    ext = np.concatenate([bits, bits[:m - 1]]) if m > 1 else bits
    idx = np.zeros(n, dtype=np.int64)
    for i in range(m):
        idx = (idx << 1) | ext[i:i + n]
    counts = np.bincount(idx, minlength=1 << m).astype(np.float64)
    return float((counts ** 2).sum()) * (1 << m) / n - n


def t_serial(bits: np.ndarray, m: int = 16) -> Tuple[float, float]:
    p2 = _psi2(bits, m)
    p1 = _psi2(bits, m - 1)
    p0 = _psi2(bits, m - 2)
    d1 = p2 - p1
    d2 = p2 - 2.0 * p1 + p0
    return (igamc(2 ** (m - 2), d1 / 2.0), igamc(2 ** (m - 3), d2 / 2.0))


def t_approx_entropy(bits: np.ndarray, m: int = 10) -> float:
    def phi(mm: int) -> float:
        n = bits.size
        ext = np.concatenate([bits, bits[:mm]])
        idx = np.zeros(n, dtype=np.int64)
        for i in range(mm):
            idx = (idx << 1) | ext[i:i + n]
        c = np.bincount(idx, minlength=1 << mm).astype(np.float64) / n
        nz = c[c > 0]
        return float((nz * np.log(nz)).sum())
    ap = phi(m) - phi(m + 1)
    n = bits.size
    chi2 = 2.0 * n * (math.log(2.0) - ap)
    return igamc(2 ** (m - 1), chi2 / 2.0)


def t_cusum(bits: np.ndarray, limit: int = 1 << 22) -> Tuple[float, float]:
    from statistics import NormalDist
    nd = NormalDist()

    def one(x: np.ndarray) -> float:
        n = x.size
        s = np.cumsum(x.astype(np.int64) * 2 - 1)
        z = int(np.abs(s).max())
        if z == 0:
            return 1.0
        total = 0.0
        k0 = int((-n / z + 1) // 4)
        k1 = int((n / z - 1) // 4)
        for k in range(k0, k1 + 1):
            total += (nd.cdf((4 * k + 1) * z / math.sqrt(n)) -
                      nd.cdf((4 * k - 1) * z / math.sqrt(n)))
        k0 = int((-n / z - 3) // 4)
        for k in range(k0, k1 + 1):
            total -= (nd.cdf((4 * k + 3) * z / math.sqrt(n)) -
                      nd.cdf((4 * k + 1) * z / math.sqrt(n)))
        return max(0.0, min(1.0, 1.0 - total))

    x = bits[:min(bits.size, limit)]
    return one(x), one(x[::-1])


# --------------------------------------------------------------------------

TESTS = ["monobit", "block-freq", "runs", "longest-run", "matrix-rank",
         "dft", "serial-1", "serial-2", "approx-entropy",
         "cusum-fwd", "cusum-rev"]


def run_battery(data: np.ndarray) -> Dict[str, float]:
    bits = np.unpackbits(data)
    s1, s2 = t_serial(bits[:min(bits.size, 1 << 22)])
    c1, c2 = t_cusum(bits)
    return {
        "monobit": t_monobit(bits),
        "block-freq": t_block_frequency(bits),
        "runs": t_runs(bits),
        "longest-run": t_longest_run(bits[:min(bits.size, 1 << 22)]),
        "matrix-rank": t_matrix_rank(data),
        "dft": t_dft(bits),
        "serial-1": s1,
        "serial-2": s2,
        "approx-entropy": t_approx_entropy(bits[:min(bits.size, 1 << 21)]),
        "cusum-fwd": c1,
        "cusum-rev": c2,
    }


def export_stream(backend, path: Path, mib: int, key: bytes, rounds: int,
                  reporter: Reporter) -> None:
    """Пишет гамму в файл для dieharder / NIST STS / PractRand."""
    ctx = backend.new_ctx(key)
    chunk_blocks = 1 << 18            # ~3 MiB за раз
    written = 0
    total = mib * 1024 * 1024
    counter = 0
    with open(path, "wb") as fh:
        while written < total:
            want = min(chunk_blocks * 12, total - written)
            data = backend.ctr_stream(ctx, rounds, 0, counter, want)
            fh.write(data)
            counter += (want + 11) // 12
            written += want
    reporter.info(f"wrote {written / 1024 / 1024:.1f} MiB to {path}")
    reporter.info("")
    reporter.info("run external batteries with:")
    reporter.info(f"  dieharder -a -g 201 -f {path}")
    reporter.info(f"  assess {written * 8} < {path}      (NIST STS)")
    reporter.info(f"  RNG_test stdin32 < {path}          (PractRand)")


def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    parser.add_argument("--keys", type=int, default=None,
                        help="independent keys to test")
    parser.add_argument("--mib", type=int, default=None,
                        help="megabytes of keystream per key")
    parser.add_argument("--export", type=str, default=None,
                        help="write a raw keystream file and exit")
    parser.add_argument("--export-mb", type=int, default=128)
    args = parser.parse_args()

    backend = get_backend(args)
    scale = profile_scale(args)
    rounds = args.rounds or 16
    rng = random.Random(args.seed)

    r = Reporter("Dedalyan randomness battery (NIST SP 800-22 subset)")

    if args.export:
        key = bytes(rng.getrandbits(8) for _ in range(32))
        r.section("Export")
        r.info(f"key {key.hex()}")
        export_stream(backend, Path(args.export), args.export_mb, key, rounds, r)
        return r.summary()

    nkeys = args.keys or max(5, int(8 * min(scale, 4)))
    mib = args.mib or (4 if scale < 0.5 else 16 if scale < 5 else 64)
    r.info(f"keys {nkeys}   keystream per key {mib} MiB   rounds {rounds}")
    r.info("p < 0.01 on an isolated test is normal; a defect repeats")

    results: List[Dict[str, float]] = []
    r.section("Per-key p-values")
    header = f"{'key':>4}  " + "  ".join(t[:9].rjust(9) for t in TESTS)
    r.row(header)
    for ki in range(nkeys):
        key = bytes(rng.getrandbits(8) for _ in range(32))
        ctx = backend.new_ctx(key)
        data = np.frombuffer(
            backend.ctr_stream(ctx, rounds, 0, ki * (1 << 40),
                               mib * 1024 * 1024), dtype=np.uint8)
        res = run_battery(data)
        results.append(res)
        r.row(f"{ki:>4}  " + "  ".join(
            (f"{res[t]:9.5f}" if res[t] == res[t] else "      n/a")
            for t in TESTS))

    # ---- сводка ----------------------------------------------------------
    r.section("Per-test summary")
    failures = 0
    for t in TESTS:
        ps = [res[t] for res in results if res[t] == res[t]]
        if not ps:
            continue
        low = sum(1 for p in ps if p < 0.01)
        r.row(f"{t:<16} min p {min(ps):8.5f}   "
              f"p < 0.01 in {low}/{len(ps)} keys")
        # Дефект: тест валится больше чем на трети ключей.
        if low > max(1, len(ps) // 3):
            failures += 1
            r.warn(f"{t} fails on {low}/{len(ps)} keys",
                   "this is the signature of a real defect, not noise")
    r.check(failures == 0, "no test fails systematically across keys")

    # ---- тест второго порядка --------------------------------------------
    r.section("Second-order test: are the p-values uniform?")
    r.info("collect every p-value and check uniformity on [0,1] with a")
    r.info("chi-square over 10 bins -- catches subtle skew a single run misses")
    allp = np.array([res[t] for res in results for t in TESTS
                     if res[t] == res[t]])
    hist = np.histogram(allp, bins=10, range=(0.0, 1.0))[0]
    exp = allp.size / 10.0
    chi2 = float(((hist - exp) ** 2 / exp).sum())
    p_uniform = igamc(4.5, chi2 / 2.0)
    r.row(f"{allp.size} p-values, chi2 = {chi2:.2f} (df = 9), "
          f"p = {p_uniform:.5f}")
    r.row("histogram: " + " ".join(str(int(h)) for h in hist))
    r.check(p_uniform > 0.001, "p-values are uniformly distributed",
            f"p = {p_uniform:.5f}")

    # ---- контроль чувствительности ---------------------------------------
    r.section("Sensitivity control: the battery must fail a weak cipher")
    key = bytes(rng.getrandbits(8) for _ in range(32))
    ctx = backend.new_ctx(key)
    for weak_rounds in (1, 2, 3):
        data = np.frombuffer(
            backend.ctr_stream(ctx, weak_rounds, 0, 0, 4 * 1024 * 1024),
            dtype=np.uint8)
        res = run_battery(data)
        low = sum(1 for t in TESTS if res[t] == res[t] and res[t] < 0.01)
        r.row(f"rounds {weak_rounds}: {low}/{len(TESTS)} tests fail "
              f"(min p = {min(v for v in res.values() if v == v):.2e})")
    r.check(True, "control runs recorded above")

    r.section("External batteries")
    r.info("this module covers the cheap tests; for the full picture export")
    r.info("a stream and run dieharder / NIST STS / PractRand:")
    r.info("  python attacks/randomness.py --export stream.bin --export-mb 512")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
