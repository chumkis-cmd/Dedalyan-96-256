"""Кросс-проверка Python и C на всех уровнях (раздел 10.1).

Спецификация требует совпадения на 10 000 случайных пар. Здесь проверяется
не только шифрование целиком, но и каждый примитив по отдельности: расхождение
в rotl или в лабиринте иначе пришлось бы искать по конечному шифротексту.

Заодно сверяемся с ref.py -- исходной эталонной реализацией из репозитория.

Запуск:  python tests/test_cross_c.py
         python tests/test_cross_c.py --samples 200000
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dedalyan as D
from dedalyan_harness import Reporter, get_backend, make_parser

DEFAULT_SAMPLES = 10_000


def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    args = parser.parse_args()
    backend = get_backend(args)
    n = args.samples or DEFAULT_SAMPLES
    rng = random.Random(args.seed)

    r = Reporter(f"Dedalyan Python <-> C parity ({n:,} random pairs)")
    r.info(f"C library: {backend.path}")

    # ---- примитивы -------------------------------------------------------
    r.section("Primitives")
    bad = [i for i in range(64) if backend.lib.dedalyan_rc(i) != D.round_constant(i)]
    r.check(not bad, "RC_i for i = 0..63", f"mismatch at {bad[:3]}")

    mism = 0
    for _ in range(20_000):
        x = rng.getrandbits(48)
        s = rng.randrange(0, 100)
        if backend.lib.dedalyan_rotl(x, s) != D.rotl(x, s):
            mism += 1
        if backend.lib.dedalyan_rotr(x, s) != D.rotr(x, s):
            mism += 1
    r.check(mism == 0, "rotl / rotr on 20 000 random (x, s), s up to 99",
            f"{mism} mismatches")

    mism = 0
    for _ in range(20_000):
        rr = rng.getrandbits(48)
        k = rng.getrandbits(48)
        i = rng.randrange(16)
        if backend.lib.dedalyan_f(rr, k, i) != D.F(rr, k, i):
            mism += 1
    r.check(mism == 0, "F on 20 000 random (R, k, i)", f"{mism} mismatches")

    # ---- лабиринт --------------------------------------------------------
    r.section("Labyrinth")
    mism = 0
    for _ in range(5_000):
        kl = rng.getrandbits(64)
        ct = backend.build_labyrinth(kl)
        pt = D.build_labyrinth(kl)
        if [list(t) for t in ct] != [list(t) for t in pt]:
            mism += 1
            continue
        x = rng.getrandbits(48)
        if backend.apply_labyrinth(x, ct) != D.apply_labyrinth(x, pt):
            mism += 1
    r.check(mism == 0, "build_labyrinth + apply_labyrinth on 5 000 K_L",
            f"{mism} mismatches")

    # ---- расписание ключей -----------------------------------------------
    r.section("Key schedule")
    mism = 0
    for _ in range(5_000):
        kb = bytes(rng.getrandbits(8) for _ in range(32))
        if backend.key_schedule(kb) != D.key_schedule(D.key_from_bytes(kb)):
            mism += 1
    r.check(mism == 0, "key_schedule on 5 000 random keys", f"{mism} mismatches")

    # ---- шифрование ------------------------------------------------------
    r.section(f"Block encryption / decryption ({n:,} pairs, all round counts)")
    mism_enc = mism_dec = mism_ref = 0
    import ref
    for _ in range(n):
        kb = bytes(rng.getrandbits(8) for _ in range(32))
        ki = D.key_from_bytes(kb)
        p = rng.getrandbits(96)
        ctx = backend.new_ctx(kb)
        cp = D.encrypt_block(p, ki)
        cc = backend.encrypt_block(ctx, p)
        if cp != cc:
            mism_enc += 1
        if D.decrypt_block(cc, ki) != backend.decrypt_block(ctx, cc):
            mism_dec += 1
        if ref.encrypt_block(p, ki) != cp:
            mism_ref += 1
    r.check(mism_enc == 0, "encrypt agrees", f"{mism_enc} mismatches")
    r.check(mism_dec == 0, "decrypt agrees", f"{mism_dec} mismatches")
    r.check(mism_ref == 0, "ref.py agrees with dedalyan.py",
            f"{mism_ref} mismatches")

    # Урезанные версии: несовпадение здесь означает разный порядок подключей.
    mism = 0
    for _ in range(2_000):
        kb = bytes(rng.getrandbits(8) for _ in range(32))
        ki = D.key_from_bytes(kb)
        p = rng.getrandbits(96)
        ctx = backend.new_ctx(kb)
        rr = rng.randrange(1, 17)
        if D.encrypt_block(p, ki, rr) != backend.encrypt_block(ctx, p, rr):
            mism += 1
    r.check(mism == 0, "round-reduced encrypt agrees for rounds 1..16",
            f"{mism} mismatches")

    # ---- трассировка -----------------------------------------------------
    r.section("Per-round trace")
    mism = 0
    for _ in range(1_000):
        kb = bytes(rng.getrandbits(8) for _ in range(32))
        p = rng.getrandbits(96)
        ctx = backend.new_ctx(kb)
        if backend.trace(ctx, p) != D.encrypt_block_trace(p, D.key_from_bytes(kb)):
            mism += 1
    r.check(mism == 0, "trace agrees on 1 000 samples", f"{mism} mismatches")

    # ---- режим CTR -------------------------------------------------------
    r.section("CTR mode")
    mism = 0
    for _ in range(300):
        kb = bytes(rng.getrandbits(8) for _ in range(32))
        length = rng.randrange(1, 200)
        data = bytes(rng.getrandbits(8) for _ in range(length))
        counter = rng.getrandbits(96)
        ctx = backend.new_ctx(kb)
        c_out = backend.ctr(ctx, counter.to_bytes(12, "big"), data)
        p_out = D.Dedalyan(kb).ctr(data, counter)
        if c_out != p_out:
            mism += 1
    r.check(mism == 0, "CTR agrees on 300 random (key, counter, length)",
            f"{mism} mismatches")

    # Перенос счётчика через 2^96 -- отдельная проверка: он легко ломается.
    kb = bytes(range(32))
    ctx = backend.new_ctx(kb)
    counter = (1 << 96) - 2
    data = bytes(40)
    r.check(backend.ctr(ctx, counter.to_bytes(12, "big"), data) ==
            D.Dedalyan(kb).ctr(data, counter),
            "CTR counter wraps 2^96 identically in both backends")

    # ---- потоковая нарезка CLI -------------------------------------------
    r.section("CLI chunking")
    r.info("the CLI processes files in chunks; if the chunk size is not a")
    r.info("multiple of 12 the counter skips a partially used keystream")
    r.info("block and everything past the first chunk decrypts to garbage")
    import cli
    r.check(cli.CHUNK % D.BLOCK_BYTES == 0,
            f"CLI chunk size {cli.CHUNK} is a multiple of {D.BLOCK_BYTES}")

    # Прогон через ту же логику, что и в CLI, на длине больше одного чанка.
    key = bytes(range(32))
    ctx = backend.new_ctx(key)
    total = cli.CHUNK * 2 + 37
    counter = bytes(12)
    pieces = []
    left = total
    while left > 0:
        take = min(cli.CHUNK, left)
        pieces.append(backend.ctr(ctx, counter, bytes(take), take))
        counter = cli.inc_counter(counter,
                                  (take + D.BLOCK_BYTES - 1) // D.BLOCK_BYTES)
        left -= take
    chunked = b"".join(pieces)
    whole = backend.ctr_stream(ctx, D.N, 0, 0, total)
    r.check(chunked == whole,
            f"chunked keystream matches the contiguous one over {total:,} bytes",
            f"first difference at byte "
            f"{next((i for i, (a, b) in enumerate(zip(chunked, whole)) if a != b), -1)}")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
