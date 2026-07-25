"""Мутационные тесты для семи «точек, где вероятны ошибки» (раздел 10.4).

Обычный тест проверяет, что реализация даёт правильный ответ. Здесь
дополнительно проверяется, что тест на это способен: для каждой типовой
ошибки написан заведомо неправильный вариант, и утверждается, что он даёт
результат, отличный от эталонного. Если мутант проходит -- значит,
соответствующая деталь спецификации ни на что не влияет либо тестовые
векторы её не покрывают.

Запуск:  python tests/test_pitfalls.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dedalyan as D
from dedalyan_harness import Reporter, make_parser

KEY_SEQ = int.from_bytes(bytes(range(32)), "big")
P_TV3 = 0x0123456789ABCDEF01234567
C_TV3 = 0x9B631FE623F15016CDBA801E
M = D.M


# --------------------------------------------------------------------------
# Мутанты. Каждый воспроизводит конкретную ошибку из списка 10.4.
# --------------------------------------------------------------------------

def mutant_1_parallel_mix(K: int) -> List[int]:
    """10.4-1: шаг (b) выполнен параллельно, а не последовательно."""
    KL, S = D.split_key(K)
    T = D.build_labyrinth(KL)
    ks = []
    for i in range(-D.WARMUP, D.N):
        S = [D.apply_labyrinth(v, T) for v in S]
        old = list(S)                      # ОШИБКА: S[3] берёт старое S[0]
        S = [(old[j] + old[(j + 1) % 4]) & M for j in range(4)]
        rot = (2 * (i % 24) + 5) % D.W
        S = [D.rotl(v, rot) for v in S]
        S = [D.apply_labyrinth(v, T) for v in S]
        if i >= 0:
            ks.append((S[i % 4] + D.round_constant(i)) & M)
    return ks


def mutant_2_no_mask(R: int, k: int, i: int) -> int:
    """10.4-2: маска после умножения потеряна.

    Существенно только там, где широкое значение попадает в сдвиг: у
    сложения, XOR и маскирования младшие 48 бит результата не зависят от
    старших, поэтому пропущенная маска перед ними ничего не меняет. А вот
    циклический сдвиг 96-битного Y смешивает старшие биты вниз -- вот где
    ошибка становится наблюдаемой.
    """
    rc = D.round_constant(i)
    Y = ((R + k) & M) * D.GAMMA1                       # ОШИБКА: до 96 бит
    x0 = ((Y + (Y >> 7)) & M) ^ ((R * D.DELTA) & M)    # сдвиг видит лишнее
    x1 = (x0 + rc) & M
    x2 = ((x1 + k) & M) ^ ((Y << 3) & M)
    return ((x2 + rc) & M) * D.GAMMA2 & M


def mutant_3_logical_shift(R: int, k: int, i: int) -> int:
    """10.4-3: сдвиги логические, а не циклические."""
    rc = D.round_constant(i)
    Y = (((R + k) & M) * D.GAMMA1) & M
    x0 = ((Y + (Y >> 7)) & M) ^ ((R * D.DELTA) & M)      # ОШИБКА
    x1 = (x0 + rc) & M
    x2 = ((x1 + k) & M) ^ ((Y << 3) & M)                 # ОШИБКА
    return (((x2 + rc) & M) * D.GAMMA2) & M


def mutant_4_truncated_mod(K: int) -> List[int]:
    """10.4-4: i mod 24 усечён к нулю и приведён к unsigned, как в C.

    Важное уточнение к спецификации: в Python эта ошибка НЕ проявляется.
    Поскольку 48 = 2 * 24, замена (i mod 24) на любого другого представителя
    класса вычетов меняет 2 * (i mod 24) ровно на кратное 48, а значит не
    меняет r_i вовсе. Опасность возникает только там, где % усекает к нулю
    И результат приводится к беззнаковому типу: −3 превращается в
    4294967293, и 4294967293 mod 48 = 13 вместо 45. Именно этот путь
    воспроизводится ниже.
    """
    KL, S = D.split_key(K)
    T = D.build_labyrinth(KL)
    ks = []
    for i in range(-D.WARMUP, D.N):
        S = [D.apply_labyrinth(v, T) for v in S]
        for j in range(4):
            S[j] = (S[j] + S[(j + 1) % 4]) & M
        trunc = i - 24 * int(i / 24)                     # C: -4 % 24 == -4
        rot = ((2 * trunc + 5) & 0xFFFFFFFF) % D.W       # C: (unsigned)(-3)
        S = [D.rotl(v, rot) for v in S]
        S = [D.apply_labyrinth(v, T) for v in S]
        if i >= 0:
            ks.append((S[i % 4] + D.round_constant(i)) & M)
    return ks


def mutant_5_progressive_selector(x: int, T: Sequence[Sequence[int]]) -> int:
    """10.4-5: селектор берётся из уже частично преобразованного значения."""
    y = x
    for j in range(12):
        beta = (y >> D.SELECTOR_BITS[j]) & 1             # ОШИБКА: y, не x
        nib = T[beta][(y >> (4 * j)) & 0xF]
        y = (y & ~(0xF << (4 * j))) | (nib << (4 * j))
    return y & M


def mutant_6_nibble_order(KL: int) -> Tuple[List[int], List[int]]:
    """10.4-6: нибблы потока nu собраны от старшего к младшему."""
    KL &= (1 << 64) - 1
    U = (KL >> 16) & M
    V = ((KL & M) ^ D.LAB_DELTA) & M
    nu: List[int] = []
    for t in range(3):
        V = D.F(V, U, t)
        nu.extend((V >> (4 * j)) & 0xF for j in range(11, -1, -1))  # ОШИБКА
    tables = []
    s = 0
    for _ in (0, 1):
        T = list(range(16))
        for j in range(15, 0, -1):
            rr = nu[s] % (j + 1)
            s += 1
            T[j], T[rr] = T[rr], T[j]
        tables.append(T)
    return tables[0], tables[1]


def mutant_7_round_index(C: int, subkeys: Sequence[int]) -> int:
    """10.4-7: при расшифровке номер раунда для RC_i тоже обращён."""
    L, R = (C >> D.W) & M, C & M
    for pos, i in enumerate(reversed(range(D.N))):
        R, L = L, R ^ D.F(L, subkeys[i], pos)            # ОШИБКА: pos вместо i
    return (L << D.W) | R


# --------------------------------------------------------------------------

def main() -> int:
    make_parser(__doc__.splitlines()[0]).parse_args()
    r = Reporter("Dedalyan pitfalls -- mutation tests for spec section 10.4")

    ref_ks = D.key_schedule(KEY_SEQ)
    T = D.build_labyrinth(0x0123456789ABCDEF)

    r.section("1. Sequential mixing in key schedule step (b)")
    mut = mutant_1_parallel_mix(KEY_SEQ)
    r.check(mut != ref_ks, "parallel variant produces different subkeys",
            f"k0: {mut[0]:012x} vs {ref_ks[0]:012x}")
    diff = sum(bin(a ^ b).count("1") for a, b in zip(mut, ref_ks))
    r.info(f"total subkey Hamming distance: {diff} / 768 bits")

    r.section("2. Masking after multiplication")
    got = mutant_2_no_mask(P_TV3 & M, ref_ks[0], 0)
    r.check(got != D.F(P_TV3 & M, ref_ks[0], 0),
            "unmasked multiply produces different F", f"{got:012x}")

    r.section("3. Cyclic vs logical shift")
    got = mutant_3_logical_shift(P_TV3 & M, ref_ks[0], 0)
    r.check(got != D.F(P_TV3 & M, ref_ks[0], 0),
            "logical shift produces different F", f"{got:012x}")
    # И прямое свойство: rotl должен быть биекцией.
    r.check(len({D.rotl(x, 7) for x in range(1 << 16)}) == 1 << 16,
            "rotl is injective (a logical shift would not be)")

    r.section("4. Negative index in warm-up: -4 mod 24 must be 20")
    mut = mutant_4_truncated_mod(KEY_SEQ)
    r.check(mut != ref_ks, "C-style truncated modulo produces different subkeys",
            f"k0: {mut[0]:012x} vs {ref_ks[0]:012x}")
    r.check(D.SHIFTS[0] == 45, "r_-4 == 45", f"got {D.SHIFTS[0]}")
    # Уточнение к спецификации: сам по себе выбор представителя i mod 24
    # безразличен, потому что 48 = 2 * 24.
    py_trunc = [(2 * (i - 24 * int(i / 24)) + 5) % 48 for i in range(-4, 16)]
    r.check(py_trunc == list(D.SHIFTS),
            "floored vs truncated mod agree in Python (48 = 2*24)",
            "hazard is C-specific: unsigned wrap, not the modulo sign")

    r.section("5. Labyrinth selectors read from the ORIGINAL x")
    x = 0x0123456789AB
    got = mutant_5_progressive_selector(x, T)
    r.check(got != D.apply_labyrinth(x, T),
            "progressive-selector variant differs", f"{got:012x}")

    r.section("6. Nibble order in the nu stream: V_0 first")
    m0, m1 = mutant_6_nibble_order(0x0123456789ABCDEF)
    r.check((m0, m1) != T, "reversed nibble order gives different tables",
            "".join("%x" % v for v in m0))

    r.section("7. Decryption keeps the ENCRYPTION round index for RC_i")
    got = mutant_7_round_index(C_TV3, ref_ks)
    r.check(got != P_TV3, "reversed round index fails to decrypt",
            f"{got:024x}")
    r.check(D.decrypt_block(C_TV3, KEY_SEQ) == P_TV3,
            "correct implementation does decrypt")

    r.section("Every mutant must break at least one published test vector")
    # Проверка полезности набора: подменяем F на мутанта и убеждаемся, что
    # TV3 перестаёт сходиться.
    orig_F = D.F
    broken = []
    for name, fn in (("no-mask multiply", mutant_2_no_mask),
                     ("logical shift", mutant_3_logical_shift)):
        D.F = fn
        try:
            if D.encrypt_block(P_TV3, KEY_SEQ) == C_TV3:
                broken.append(name)
        finally:
            D.F = orig_F
    r.check(not broken, "TV3 detects both F mutants",
            "" if not broken else f"undetected: {broken}")

    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
