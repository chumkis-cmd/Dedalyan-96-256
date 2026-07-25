"""Проверка всех тестовых векторов раздела 8 спецификации.

Проверяются и промежуточные величины -- таблицы лабиринта и подключи:
они локализуют ошибку до конкретного этапа, а пораундовая трассировка TV3 --
до конкретного раунда.

Запуск:  python tests/test_vectors.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dedalyan as D
from dedalyan_harness import Reporter, fmt_bits, make_parser

# ---- ожидаемые значения из спецификации ----------------------------------

LAB_ZERO = ("a9dc013f46e85b27", "a1e4c03d76b9f825")
LAB_SEQ = ("3bed640f928c157a", "e68359f1b4cd207a")
LAB_APPLY = (0x0123456789AB, 0xE6ED640F92CD)

RC_TABLE = [
    0x3188EBE1E0B8, 0xCFC0659B6002, 0x6DF7DF54DF4C, 0x0C2F590E5E96,
    0xAA66D2C7DDE0, 0x489E4C815D2A, 0xE6D5C63ADC74, 0x850D3FF45BBE,
    0x2344B9ADDB08, 0xC17C33675A52, 0x5FB3AD20D99C, 0xFDEB26DA58E6,
    0x9C22A093D830, 0x3A5A1A4D577A, 0xD8919406D6C4, 0x76C90DC0560E,
]

KS_ZERO = [
    0x9864A848B6D4, 0x66845D0326D1, 0x9CE6EFF8CD60, 0xDE534C0AEEC3,
    0x84ED264AC5BB, 0xAEDD6A826C93, 0x2C4D8A772D04, 0xABA7EEC66F0F,
    0xFF822A71A117, 0x13776BBC1FBF, 0x499DA61DEBDF, 0xFF1503BD8AAC,
    0xDC17510F5FAE, 0x3A08B3DAB4F4, 0x63BBB6A9252B, 0x30A6E63F94E6,
]

KS_SEQ = [
    0x352B543E645D, 0x3BB3B319FA45, 0xBA34EE3B5816, 0xF5015D474FAA,
    0x18454389852B, 0x545DAA0A6112, 0x51F0A63D8E60, 0xB9BDDDA2E38C,
    0x4A92ED2D2816, 0x47CDD4E8E543, 0xE10755F1FC74, 0xB7F0A3BD6E0C,
    0x3D5D558B3B7F, 0xE04B6A7BD904, 0x558C5A714B1B, 0xF9958A46E7BF,
]

KEY_SEQ = int.from_bytes(bytes(range(32)), "big")
KEY_ONES = (1 << 256) - 1

# (имя, P, K, C)
TEST_VECTORS = [
    ("TV1", 0x000000000000000000000000, 0, 0x70A4CEAA4A6737FB294A0EDF),
    ("TV2", 0x000000000000000000000001, 0, 0x85A903C2A6B73B50F00E1405),
    ("TV3", 0x0123456789ABCDEF01234567, KEY_SEQ, 0x9B631FE623F15016CDBA801E),
    ("TV4", (1 << 96) - 1, KEY_ONES, 0xA936A309096319F869F6549D),
]

# Раздел 8.5: (F, L, R) после каждого раунда для TV3.
TV3_TRACE = [
    (0x229E7F0EB588, 0xCDEF01234567, 0x23BD3A693C23),
    (0x94E01BC2AAD8, 0x23BD3A693C23, 0x590F1AE1EFBF),
    (0xA9C66A1086E7, 0x590F1AE1EFBF, 0x8A7B5079BAC4),
    (0xFD9E1674955A, 0x8A7B5079BAC4, 0xA4910C957AE5),
    (0xA7C66B61B1B1, 0xA4910C957AE5, 0x2DBD3B180B75),
    (0x82336D2325BE, 0x2DBD3B180B75, 0x26A261B65F5B),
    (0x05734BE79F0D, 0x26A261B65F5B, 0x28CE70FF9478),
    (0x7E3FEBC6F8B6, 0x28CE70FF9478, 0x589D8A70A7ED),
    (0x267030894057, 0x589D8A70A7ED, 0x0EBE4076D42F),
    (0xC572310F4B4C, 0x0EBE4076D42F, 0x9DEFBB7FECA1),
    (0x5F51EC67DD59, 0x9DEFBB7FECA1, 0x51EFAC110976),
    (0xBD7201F955D8, 0x51EFAC110976, 0x209DBA86B979),
    (0x60E553C6F23F, 0x209DBA86B979, 0x310AFFD7FB49),
    (0x1FB2103A188A, 0x310AFFD7FB49, 0x3F2FAABCA1F3),
    (0xAA69E031D8B8, 0x3F2FAABCA1F3, 0x9B631FE623F1),
    (0x6F39670621ED, 0x9B631FE623F1, 0x5016CDBA801E),
]

SHIFTS_SPEC = [45, 47, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19,
               21, 23, 25, 27, 29, 31, 33, 35]

SELECTOR_BITS_SPEC = [26, 30, 34, 38, 42, 46, 2, 6, 10, 14, 18, 22]


def tbl(T) -> str:
    return "".join("%x" % v for v in T)


def main() -> int:
    parser = make_parser(__doc__.splitlines()[0])
    parser.parse_args()
    r = Reporter("Dedalyan test vectors (spec section 8)")

    # ---- раздел 2 --------------------------------------------------------
    r.section("2. Round constants RC_i = ((i + 44) * PHI) mod 2^48")
    bad = [i for i in range(16) if D.round_constant(i) != RC_TABLE[i]]
    r.check(not bad, "RC table matches spec",
            "" if not bad else f"mismatch at i={bad}")

    r.section("7. Rotation amounts r_i and 6.3 selector bits b_j")
    r.check(list(D.SHIFTS) == SHIFTS_SPEC, "r_i for i = -4..15",
            f"got {list(D.SHIFTS)[:4]}...")
    r.check(list(D.SELECTOR_BITS) == SELECTOR_BITS_SPEC, "b_j for j = 0..11")

    # ---- раздел 8.1 ------------------------------------------------------
    r.section("8.1. Labyrinth")
    T0, T1 = D.build_labyrinth(0x0000000000000000)
    r.check(tbl(T0) == LAB_ZERO[0], "T0 for KL = 0", tbl(T0))
    r.check(tbl(T1) == LAB_ZERO[1], "T1 for KL = 0", tbl(T1))

    T0, T1 = D.build_labyrinth(0x0123456789ABCDEF)
    r.check(tbl(T0) == LAB_SEQ[0], "T0 for KL = 0123456789ABCDEF", tbl(T0))
    r.check(tbl(T1) == LAB_SEQ[1], "T1 for KL = 0123456789ABCDEF", tbl(T1))

    got = D.apply_labyrinth(LAB_APPLY[0], (T0, T1))
    r.check(got == LAB_APPLY[1], "Lab(0x0123456789AB)", fmt_bits(got))

    # Обе таблицы обязаны быть перестановками -- иначе лабиринт необратим
    # по построению и Фишер--Йетс реализован неверно.
    r.check(sorted(T0) == list(range(16)) and sorted(T1) == list(range(16)),
            "T0 and T1 are permutations of 0..15")

    # ---- разделы 8.2 и 8.3 -----------------------------------------------
    r.section("8.2/8.3. Key schedule")
    ks = D.key_schedule(0)
    bad = [i for i in range(16) if ks[i] != KS_ZERO[i]]
    r.check(not bad, "subkeys for K = 0",
            "" if not bad else f"mismatch at k[{bad[0]}] = {fmt_bits(ks[bad[0]])}")

    ks = D.key_schedule(KEY_SEQ)
    bad = [i for i in range(16) if ks[i] != KS_SEQ[i]]
    r.check(not bad, "subkeys for K = 000102..1e1f",
            "" if not bad else f"mismatch at k[{bad[0]}] = {fmt_bits(ks[bad[0]])}")

    r.check(all(0 <= k <= D.M for k in ks), "all subkeys fit in 48 bits")

    # ---- раздел 8.4 ------------------------------------------------------
    r.section("8.4. Encryption vectors")
    for name, P, K, C in TEST_VECTORS:
        got = D.encrypt_block(P, K)
        r.check(got == C, f"{name} encrypt", f"{got:024x}")
        back = D.decrypt_block(C, K)
        r.check(back == P, f"{name} decrypt", f"{back:024x}")

    # ---- раздел 8.5 ------------------------------------------------------
    r.section("8.5. Per-round trace for TV3 (localises errors to one round)")
    trace = D.encrypt_block_trace(TEST_VECTORS[2][1], TEST_VECTORS[2][2])
    first_bad = None
    for i, ((f, l, rr), (ef, el, er)) in enumerate(zip(trace, TV3_TRACE)):
        if (f, l, rr) != (ef, el, er):
            first_bad = (i, f, l, rr, ef, el, er)
            break
    if first_bad is None:
        r.check(True, "all 16 rounds match")
    else:
        i, f, l, rr, ef, el, er = first_bad
        r.check(False, f"round {i} mismatch",
                f"got F={fmt_bits(f)} L={fmt_bits(l)} R={fmt_bits(rr)} / "
                f"want F={fmt_bits(ef)} L={fmt_bits(el)} R={fmt_bits(er)}")

    # ---- сверка с C ------------------------------------------------------
    r.section("C backend parity")
    from dedalyan_c import backend
    if not backend.available:
        r.warn("C backend not built", "skipping parity checks; run build.ps1")
    else:
        ok = True
        for name, P, K, C in TEST_VECTORS:
            ctx = backend.new_ctx(D.key_to_bytes(K))
            ok &= backend.encrypt_block(ctx, P) == C
            ok &= backend.decrypt_block(ctx, C) == P
        r.check(ok, "C reproduces all four vectors")

        cT = backend.build_labyrinth(0x0123456789ABCDEF)
        r.check(tbl(cT[0]) == LAB_SEQ[0] and tbl(cT[1]) == LAB_SEQ[1],
                "C labyrinth matches spec")
        r.check(backend.key_schedule(D.key_to_bytes(KEY_SEQ)) == KS_SEQ,
                "C key schedule matches spec")

        ctx = backend.new_ctx(D.key_to_bytes(KEY_SEQ))
        ctrace = backend.trace(ctx, TEST_VECTORS[2][1])
        r.check(ctrace == TV3_TRACE, "C per-round trace matches spec")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
