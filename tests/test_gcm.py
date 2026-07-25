"""Тесты Dedalyan-GCM-96 и кадрированного файлового формата.

Проверяется четырьмя слоями:

1. Поле GF(2^96) — аксиомы и согласие с независимой реализацией в
   естественном порядке бит.
2. Схема — векторы, привязка к спецификации, паритет C и Python.
3. Аутентификация — каждая подделка обязана быть отвергнута.
4. Файловый формат — перестановка, усечение и склейка кадров.

Запуск:  python tests/test_gcm.py
"""

from __future__ import annotations

import io
import os
import random
import secrets
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dedalyan as D
import dedalyan_file as F
import dedalyan_gcm as G
from dedalyan_harness import Reporter, make_parser

N = 96
POLY = (1 << N) | 0x641           # x^96 + x^10 + x^9 + x^6 + 1

# Векторы зафиксированы, чтобы поймать любое непреднамеренное изменение схемы.
KAT = [
    (bytes(32), bytes(8), b"", b"",
     "85a903c2a6b73b50f00e1405"),
    (bytes(32), bytes(8), b"", b"abc",
     "a35e09ccfe25a64d84b150ad27ac79"),
    (bytes(range(32)), bytes(range(8)), b"aad", b"The quick brown fox",
     "d0cc99668539dce92ab255d577c559cec8cb5801ac0ef4cfc82345b9595ac4"),
    (bytes(range(32)), bytes(8), b"", bytes(12),
     "0b704654131e3b7f3891e11a1ebe61c9ed5d708118f0ed24"),
]


def nat_mul(a: int, b: int) -> int:
    """Независимое умножение в естественном порядке бит (бит j = коэф. x^j)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if (a >> N) & 1:
            a ^= POLY
    return r


def reflect(v: int) -> int:
    """Естественный порядок -> отражённый GCM."""
    out = 0
    for j in range(N):
        if (v >> j) & 1:
            out |= 1 << (N - 1 - j)
    return out


def main() -> int:
    make_parser(__doc__.splitlines()[0]).parse_args()
    r = Reporter("Dedalyan-GCM-96 and framed file format")
    rng = random.Random(20260725)

    def rb(n):
        return bytes(rng.getrandbits(8) for _ in range(n))

    # ---- 1. Поле ---------------------------------------------------------
    r.section("1. GF(2^96) field arithmetic")
    r.info("polynomial x^96 + x^10 + x^9 + x^6 + 1; GCM bit convention,")
    r.info("so the MSB of a block is the coefficient of x^0")

    mismatch = sum(
        G.gf_mul(reflect(a), reflect(b)) != reflect(nat_mul(a, b))
        for a, b in ((rng.getrandbits(N), rng.getrandbits(N))
                     for _ in range(1500)))
    r.check(mismatch == 0,
            "agrees with an independent natural-order implementation",
            f"{mismatch} mismatches in 1500")

    one = reflect(1)
    r.check(one == 1 << (N - 1), "field identity is the top bit",
            f"{one:024x}")
    r.check(G.R == 0x826000000000000000000000,
            "reduction constant matches the polynomial", f"{G.R:024x}")

    ok_comm = ok_assoc = ok_distr = ok_id = True
    for _ in range(800):
        a, b, c = (rng.getrandbits(N) for _ in range(3))
        ok_comm &= G.gf_mul(a, b) == G.gf_mul(b, a)
        ok_assoc &= G.gf_mul(G.gf_mul(a, b), c) == G.gf_mul(a, G.gf_mul(b, c))
        ok_distr &= G.gf_mul(a, b ^ c) == G.gf_mul(a, b) ^ G.gf_mul(a, c)
        ok_id &= G.gf_mul(a, one) == a
    r.check(ok_comm, "multiplication is commutative")
    r.check(ok_assoc, "multiplication is associative")
    r.check(ok_distr, "multiplication distributes over XOR")
    r.check(ok_id, "identity element behaves")

    # a^(2^96-1) == 1 для любого ненулевого a: это и есть подтверждение
    # того, что многочлен неприводим, а структура -- поле.
    def gf_pow(a, e):
        acc = one
        while e:
            if e & 1:
                acc = G.gf_mul(acc, a)
            a = G.gf_mul(a, a)
            e >>= 1
        return acc

    ok_order = all(gf_pow(rng.getrandbits(N) | 1, (1 << N) - 1) == one
                   for _ in range(12))
    r.check(ok_order, "a^(2^96-1) == 1 for nonzero a",
            "independent confirmation that the polynomial is irreducible")
    r.check(all(G.gf_mul(rng.getrandbits(N) | 1, rng.getrandbits(N) | 1) != 0
                for _ in range(800)), "no zero divisors")

    # ---- 2. Схема --------------------------------------------------------
    r.section("2. Scheme: vectors and anchoring to the spec")
    bad = [i for i, (k, n, a, p, want) in enumerate(KAT)
           if G.seal(k, n, p, a).hex() != want]
    r.check(not bad, f"{len(KAT)} known-answer vectors", f"failed: {bad}")

    # Вырожденный случай GCM обязан сойтись с опубликованными векторами
    # спецификации -- это независимая привязка схемы к разделу 8.
    h0 = G.GcmContext(bytes(32)).h
    r.check(h0 == 0x70A4CEAA4A6737FB294A0EDF,
            "H = E_K(0) for K=0 equals spec vector TV1", f"{h0:024x}")
    empty_tag = G.seal(bytes(32), bytes(8), b"", b"")
    r.check(empty_tag.hex() == "85a903c2a6b73b50f00e1405",
            "tag of the empty message equals spec vector TV2",
            "GHASH is 0, so the tag is E_K(J0) = E_K(1)")

    # ---- 3. Обратимость --------------------------------------------------
    r.section("3. Roundtrip across lengths")
    key = rb(32)
    ctx = G.GcmContext(key)
    lengths = [0, 1, 11, 12, 13, 23, 24, 25, 143, 144, 145, 5000]
    lengths += [rng.randint(0, 3000) for _ in range(40)]
    bad = 0
    for n in lengths:
        nonce, pt = rb(8), rb(n)
        aad = rb(rng.choice([0, 1, 11, 12, 13, 40]))
        if ctx.open_(nonce, ctx.seal(nonce, pt, aad), aad) != pt:
            bad += 1
    r.check(bad == 0, f"{len(lengths)} lengths incl. block boundaries",
            f"{bad} failures")

    # ---- 4. Паритет C и Python -------------------------------------------
    r.section("4. C backend parity")
    from dedalyan_c import backend
    if not backend.available:
        r.warn("C backend not built", "run build.ps1; skipping parity checks")
    else:
        cctx = backend.gcm_new(key)
        r.check(backend.gcm_h(cctx) == ctx.h, "H matches")

        # Три независимые реализации умножения: таблица C, побитовое C,
        # побитовое Python.
        hb = ctx.h.to_bytes(12, "big")
        bad_t = bad_p = 0
        for _ in range(400):
            x = rb(12)
            ref = backend.gcm_mul_ref(x, hb)
            bad_t += backend.gcm_mul_h(cctx, x) != ref
            bad_p += G.gf_mul(int.from_bytes(x, "big"),
                              ctx.h).to_bytes(12, "big") != ref
        r.check(bad_t == 0, "C table multiply == C bitwise reference",
                f"{bad_t} mismatches")
        r.check(bad_p == 0, "Python multiply == C bitwise reference",
                f"{bad_p} mismatches")

        bad = sum(backend.gcm_ghash(cctx, d) !=
                  G.ghash(ctx.h, d).to_bytes(12, "big")
                  for d in (rb(12 * rng.randint(0, 6)) for _ in range(150)))
        r.check(bad == 0, "GHASH agrees", f"{bad} mismatches")

        # Python с принудительно отключённым C -- отдельный путь кода.
        pyctx = G.GcmContext(key, force_python=True)
        bad_s = bad_x = 0
        for n in (0, 1, 12, 13, 500, 1237):
            nonce, pt, aad = rb(8), rb(n), rb(17)
            cs = backend.gcm_seal(cctx, nonce, pt, aad)
            ps = pyctx.seal(nonce, pt, aad)
            bad_s += cs != ps
            bad_x += backend.gcm_open(cctx, nonce, ps, aad) != pt
            bad_x += pyctx.open_(nonce, cs, aad) != pt
        r.check(bad_s == 0, "seal byte-identical in both backends", f"{bad_s}")
        r.check(bad_x == 0, "each backend opens the other's output", f"{bad_x}")

    # ---- 5. Аутентификация -----------------------------------------------
    r.section("5. Every tampering must be rejected")
    nonce, pt, aad = rb(8), rb(300), rb(24)
    sealed = ctx.seal(nonce, pt, aad)

    def rejected(s, ad=aad, nn=nonce) -> bool:
        try:
            ctx.open_(nn, s, ad)
            return False
        except G.AuthenticationError:
            return True

    # Каждый байт: и шифротекста, и тега.
    flips = sum(
        rejected(sealed[:i] + bytes([sealed[i] ^ 0x01]) + sealed[i + 1:])
        for i in range(len(sealed)))
    r.check(flips == len(sealed),
            f"single-bit flip rejected at all {len(sealed)} byte positions",
            f"{len(sealed) - flips} accepted")

    r.check(rejected(sealed, ad=aad + b"x"), "modified AAD rejected")
    r.check(rejected(sealed, ad=b""), "removed AAD rejected")
    r.check(rejected(sealed, nn=bytes([nonce[0] ^ 1]) + nonce[1:]),
            "modified nonce rejected")
    r.check(rejected(sealed[:-1]), "truncated by one byte rejected")
    r.check(rejected(sealed + b"\x00"), "extended by one byte rejected")

    other = G.GcmContext(rb(32))
    try:
        other.open_(nonce, sealed, aad)
        r.check(False, "wrong key rejected")
    except G.AuthenticationError:
        r.check(True, "wrong key rejected")

    # Тег обязан зависеть от длины AAD, а не только от её содержимого:
    # иначе можно перекинуть байты между AAD и шифротекстом.
    s1 = ctx.seal(nonce, b"AB", b"CD")
    s2 = ctx.seal(nonce, b"ABCD", b"")
    r.check(s1[-12:] != s2[-12:],
            "length block separates AAD from ciphertext")

    # ---- 6. Файловый формат ----------------------------------------------
    r.section("6. Framed file format")
    fkey = rb(32)
    sizes = [0, 1, F.MIN_CHUNK - 1, F.MIN_CHUNK, F.MIN_CHUNK + 1,
             F.MIN_CHUNK * 3, F.MIN_CHUNK * 3 + 7, 50_000]
    bad = 0
    for size in sizes:
        data = secrets.token_bytes(size)
        buf = io.BytesIO()
        F.encrypt_stream(io.BytesIO(data), buf, key=fkey,
                         chunk_size=F.MIN_CHUNK)
        out = io.BytesIO()
        F.decrypt_stream(io.BytesIO(buf.getvalue()), out, key=fkey)
        bad += out.getvalue() != data
    r.check(bad == 0, f"roundtrip over {len(sizes)} sizes incl. exact "
                      f"multiples of the chunk", f"{bad} failures")

    data = secrets.token_bytes(F.MIN_CHUNK * 4 + 100)
    buf = io.BytesIO()
    F.encrypt_stream(io.BytesIO(data), buf, key=fkey, chunk_size=F.MIN_CHUNK)
    blob = buf.getvalue()
    frame = F.MIN_CHUNK + G.TAG_BYTES
    hdr = F.HEADER_BYTES

    def dec_fails(b) -> bool:
        try:
            F.decrypt_stream(io.BytesIO(b), io.BytesIO(), key=fkey)
            return False
        except (G.AuthenticationError, F.FileFormatError):
            return True

    r.check(dec_fails(blob[:hdr + frame * 2]),
            "truncation detected (no final frame)")
    # Перестановка кадров 0 и 1.
    swapped = (blob[:hdr] + blob[hdr + frame:hdr + 2 * frame] +
               blob[hdr:hdr + frame] + blob[hdr + 2 * frame:])
    r.check(dec_fails(swapped), "frame reordering detected")
    # Порча заголовка: меняем идентификатор файла.
    bad_hdr = bytearray(blob)
    bad_hdr[hdr - 1] ^= 0x01
    r.check(dec_fails(bytes(bad_hdr)), "header tampering detected")
    # Склейка кадров из другого файла на том же ключе.
    other_buf = io.BytesIO()
    F.encrypt_stream(io.BytesIO(secrets.token_bytes(len(data))), other_buf,
                     key=fkey, chunk_size=F.MIN_CHUNK)
    spliced = blob[:hdr + frame] + other_buf.getvalue()[hdr + frame:]
    r.check(dec_fails(spliced), "cross-file frame splicing detected")
    r.check(dec_fails(b"NOTMAGIC" + blob[8:]), "bad magic rejected")

    # Заявленный размер кадра не должен позволять выделить гигабайты
    # до всякой аутентификации.
    huge = bytearray(blob)
    struct.pack_into(">I", huge, 8 + 1 + 1 + 1 + 1 + 4, 1 << 30)
    r.check(dec_fails(bytes(huge)), "absurd chunk size rejected before use")

    # ---- 7. Пароль и файлы на диске --------------------------------------
    r.section("7. Password mode and on-disk files")
    try:
        import argon2  # noqa: F401
        have_argon2 = True
    except ImportError:
        have_argon2 = False

    if not have_argon2:
        r.warn("argon2-cffi not installed", "skipping password mode")
    else:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src, enc, dec = td / "a.bin", td / "a.ded", td / "a.out"
            payload = secrets.token_bytes(70_000)
            src.write_bytes(payload)
            F.encrypt_file(src, enc, password="пароль", chunk_size=F.MIN_CHUNK,
                           memory_kib=8 * 1024, time_cost=1)
            F.decrypt_file(enc, dec, password="пароль")
            r.check(dec.read_bytes() == payload, "password roundtrip on disk")
            r.check(enc.stat().st_size > payload.__len__(),
                    "container carries header and tags",
                    f"{enc.stat().st_size - len(payload)} bytes overhead")

            dec.unlink()
            try:
                F.decrypt_file(enc, dec, password="не тот")
                r.check(False, "wrong password rejected")
            except G.AuthenticationError:
                r.check(True, "wrong password rejected")
            r.check(not dec.exists(),
                    "no partial output left behind after a failed decrypt",
                    "a half-written file would look like success")

            r.check(not (td / "a.out.part").exists(),
                    "temporary .part file cleaned up")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
