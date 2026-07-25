"""Обратимость: decrypt(encrypt(P, K), K) == P (раздел 10.2).

По умолчанию 100 000 случайных пар (текст, ключ) на C-бэкенде и меньшая
выборка на Python -- чистый Python даёт около 700 пар в секунду, и полный
прогон занял бы минуты.

Дополнительно проверяется обратимость на всех урезанных числах раундов
1..16: ошибка в порядке подключей при расшифровке проявляется именно там.

Запуск:  python tests/test_roundtrip.py
         python tests/test_roundtrip.py --samples 1000000
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dedalyan as D
from dedalyan_harness import (Reporter, get_backend, jobs_of, make_parser,
                              parallel_map, random_key, split_work)

DEFAULT_SAMPLES = 100_000
PYTHON_SAMPLES = 2_000


def _worker(task):
    """Проверяет chunk случайных пар. Возвращает (проверено, первый отказ)."""
    seed, chunk, rounds = task
    from dedalyan_c import backend
    rng = random.Random(seed)
    for _ in range(chunk):
        key = bytes(rng.getrandbits(8) for _ in range(32))
        p = rng.getrandbits(96)
        ctx = backend.new_ctx(key)
        c = backend.encrypt_block(ctx, p, rounds)
        if backend.decrypt_block(ctx, c, rounds) != p:
            return chunk, (key.hex(), p, rounds)
    return chunk, None


def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    args = parser.parse_args()
    n = args.samples or DEFAULT_SAMPLES
    rounds = args.rounds or D.N

    r = Reporter(f"Dedalyan roundtrip -- {n:,} random (plaintext, key) pairs")

    # ---- Python-эталон ---------------------------------------------------
    r.section(f"Pure Python reference ({PYTHON_SAMPLES:,} pairs)")
    rng = random.Random(args.seed ^ 0xA5A5)
    bad = None
    for _ in range(PYTHON_SAMPLES):
        k = rng.getrandbits(256)
        p = rng.getrandbits(96)
        if D.decrypt_block(D.encrypt_block(p, k, rounds), k, rounds) != p:
            bad = (k, p)
            break
    r.check(bad is None, f"decrypt(encrypt(P,K),K) == P at {rounds} rounds",
            "" if bad is None else f"K={bad[0]:064x} P={bad[1]:024x}")

    # Отдельно -- граничные значения. Случайная выборка их почти не задевает.
    r.section("Edge cases")
    edge_p = [0, 1, (1 << 96) - 1, (1 << 48) - 1, (1 << 48),
              0xFFFFFFFFFFFF000000000000, 0x000000000000FFFFFFFFFFFF]
    edge_k = [0, 1, (1 << 256) - 1, (1 << 192) - 1, 1 << 192,
              int.from_bytes(bytes(range(32)), "big")]
    fails = [(p, k) for p in edge_p for k in edge_k
             if D.decrypt_block(D.encrypt_block(p, k), k) != p]
    r.check(not fails, f"{len(edge_p) * len(edge_k)} edge (P, K) combinations",
            "" if not fails else f"{len(fails)} failures")

    # Шифрование не должно быть тождественным ни на одной граничной паре.
    ident = [(p, k) for p in edge_p for k in edge_k
             if D.encrypt_block(p, k) == p]
    r.check(not ident, "no fixed points on edge cases",
            "" if not ident else f"{len(ident)} fixed points")

    # ---- урезанные версии ------------------------------------------------
    r.section("Round-reduced versions (Dedalyan-96/256-rN)")
    key = int.from_bytes(bytes(range(32)), "big")
    bad_rounds = []
    for rr in range(1, D.N + 1):
        rng2 = random.Random(args.seed + rr)
        for _ in range(50):
            p = rng2.getrandbits(96)
            if D.decrypt_block(D.encrypt_block(p, key, rr), key, rr) != p:
                bad_rounds.append(rr)
                break
    r.check(not bad_rounds, "roundtrip holds for rounds 1..16",
            "" if not bad_rounds else f"broken at rounds {bad_rounds}")

    # ---- основной прогон на C -------------------------------------------
    backend = get_backend(args)
    if backend is None:
        r.warn("C backend skipped", "--python given")
        return r.summary()

    r.section(f"C backend ({n:,} pairs, {jobs_of(args)} processes)")
    jobs = jobs_of(args)
    chunks = split_work(n, jobs)
    tasks = [(args.seed + i * 7919, c, rounds) for i, c in enumerate(chunks)]
    results = parallel_map(_worker, tasks, jobs)
    total = sum(c for c, _ in results)
    failures = [f for _, f in results if f is not None]
    r.check(not failures, f"{total:,} pairs verified",
            "" if not failures else f"first failure: {failures[0]}")

    # Кросс-проверка Python <-> C на общей выборке.
    r.section("Python vs C agreement (10 000 pairs, spec 10.1)")
    rng = random.Random(args.seed ^ 0xC0FFEE)
    mism = 0
    for _ in range(10_000):
        kb = bytes(rng.getrandbits(8) for _ in range(32))
        p = rng.getrandbits(96)
        ctx = backend.new_ctx(kb)
        if backend.encrypt_block(ctx, p) != D.encrypt_block(p, D.key_from_bytes(kb)):
            mism += 1
    r.check(mism == 0, "identical ciphertexts", f"{mism} mismatches")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
