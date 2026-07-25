"""Dedalyan-96/256 -- эталонная реализация на Python.

Соответствует спецификации версии 1.0 (dedalyan-spec.md).

ВНИМАНИЕ (раздел 0 спецификации): шифр не предназначен для защиты реальных
данных. Его стойкость не доказана и не проверялась независимыми
криптоаналитиками.

Приоритет этого модуля -- читаемость, а не скорость: это эталон, по которому
проверяются остальные реализации. Быстрый путь -- в ``dedalyan_c.py``.

Публичный интерфейс (раздел 10.1 спецификации)::

    encrypt_block(P: int, K: int) -> int
    decrypt_block(C: int, K: int) -> int
    key_schedule(K: int) -> list[int]
    build_labyrinth(KL: int) -> tuple[list[int], list[int]]
    apply_labyrinth(x: int, T) -> int

Дополнительно (раздел 10.3): параметр ``rounds`` для урезанных версий,
режим CTR, байтовые обёртки и пораундовая трассировка.
"""

from __future__ import annotations

from typing import Iterator, List, Sequence, Tuple

__all__ = [
    # параметры
    "W", "M", "N", "WARMUP", "BLOCK_BITS", "BLOCK_BYTES", "KEY_BITS", "KEY_BYTES",
    # константы
    "GAMMA1", "DELTA", "GAMMA2", "PHI", "LAB_DELTA", "RC",
    # примитивы
    "rotl", "rotr", "round_constant", "F",
    # лабиринт и расписание
    "build_labyrinth", "apply_labyrinth", "key_schedule",
    # шифрование
    "encrypt_block", "decrypt_block",
    "encrypt_block_with_subkeys", "decrypt_block_with_subkeys",
    "encrypt_block_trace",
    # удобные обёртки
    "Dedalyan", "ctr_keystream", "ctr_crypt",
    "block_to_bytes", "bytes_to_block", "key_from_bytes", "key_to_bytes",
]

# --------------------------------------------------------------------------
# Раздел 1. Параметры
# --------------------------------------------------------------------------

W = 48                      # размер слова, бит
M = (1 << W) - 1            # 0xFFFFFFFFFFFF -- маска слова
N = 16                      # число рабочих раундов
WARMUP = 4                  # шагов прогрева расписания ключей (i = -4..-1)

BLOCK_BITS = 2 * W          # 96
BLOCK_BYTES = BLOCK_BITS // 8   # 12
KEY_BITS = 256
KEY_BYTES = KEY_BITS // 8       # 32

# --------------------------------------------------------------------------
# Раздел 2. Константы
# --------------------------------------------------------------------------

GAMMA1 = 0x46BD0CD0DCAD     # γ₁ -- множитель в Y
DELTA = 0x128F8FB70F        # δ  -- множитель при R
GAMMA2 = 0x46BB83114CCF     # γ₂ -- множитель на выходе F
PHI = 0x9E3779B97F4A        # φ  -- основа раундовых констант
LAB_DELTA = 0x5A827999A2B1  # Δ  -- доменная константа лабиринта

# Все три множителя нечётные: по модулю 2^48 обратимы ровно нечётные числа.
assert GAMMA1 & 1 and DELTA & 1 and GAMMA2 & 1


def round_constant(i: int) -> int:
    """RC_i = ((i + 44) ⊙ φ) mod 2^48."""
    return ((i + 44) * PHI) & M


#: Предвычисленная таблица раундовых констант для i = 0..15 (раздел 2).
RC: Tuple[int, ...] = tuple(round_constant(i) for i in range(N))


# --------------------------------------------------------------------------
# Примитивы
# --------------------------------------------------------------------------

def rotl(x: int, s: int) -> int:
    """Циклический (не логический!) сдвиг влево в 48-битном регистре.

    Точка ошибки 10.4-3: при s >= 48 берётся s mod 48.
    """
    s %= W
    return ((x << s) | (x >> (W - s))) & M


def rotr(x: int, s: int) -> int:
    """Циклический сдвиг вправо в 48-битном регистре."""
    s %= W
    return ((x >> s) | (x << (W - s))) & M


# --------------------------------------------------------------------------
# Раздел 3. Раундовая функция
# --------------------------------------------------------------------------

def F(R: int, k: int, i: int) -> int:
    """Раундовая функция ARX.

        Y  = (R ⊞ k) ⊙ γ₁
        x₀ = (Y ⊞ (Y ⋙ 7)) ⊕ (R ⊙ δ)
        x₁ = x₀ ⊞ RC_i
        x₂ = (x₁ ⊞ k) ⊕ (Y ⋘ 3)
        F  = (x₂ ⊞ RC_i) ⊙ γ₂

    F не биекция по R -- в сети Фейстеля это допустимо.

    Точка ошибки 10.4-2: произведение двух 48-битных чисел имеет до 96 бит,
    маскировать обязательно после каждого умножения.
    """
    rc = round_constant(i)
    Y = (((R + k) & M) * GAMMA1) & M
    x0 = ((Y + rotr(Y, 7)) & M) ^ ((R * DELTA) & M)
    x1 = (x0 + rc) & M
    x2 = ((x1 + k) & M) ^ rotl(Y, 3)
    return (((x2 + rc) & M) * GAMMA2) & M


# --------------------------------------------------------------------------
# Раздел 6. Лабиринт
# --------------------------------------------------------------------------

#: Позиции бит-селекторов: b_j = 4·((j + 6) mod 12) + 2 (раздел 6.3).
SELECTOR_BITS: Tuple[int, ...] = tuple(4 * ((j + 6) % 12) + 2 for j in range(12))


def build_labyrinth(KL: int) -> Tuple[List[int], List[int]]:
    """Строит пару перестановок (T₀, T₁) множества {0..15} из 64-битного K_L.

    6.1 Расширение: 64 бит мало для двух перестановок 16 элементов
    (нужно ≈88 бит), поэтому материал расширяется раундовой функцией --
    три вызова F дают поток из 36 нибблов, используются первые 30.

    6.2 Построение: Фишер--Йетс, потребляющий поток последовательно.
    """
    KL &= (1 << 64) - 1

    U = (KL >> 16) & M              # старшие 48 бит K_L
    V = ((KL & M) ^ LAB_DELTA) & M

    # Точка ошибки 10.4-6: порядок нибблов -- от младшего к старшему, V₀ первым.
    nu: List[int] = []
    for t in range(3):
        V = F(V, U, t)
        nu.extend((V >> (4 * j)) & 0xF for j in range(12))

    tables: List[List[int]] = []
    s = 0
    for _t in (0, 1):
        T = list(range(16))
        for j in range(15, 0, -1):
            r = nu[s] % (j + 1)
            s += 1
            T[j], T[r] = T[r], T[j]
        tables.append(T)

    return tables[0], tables[1]


def apply_labyrinth(x: int, T: Sequence[Sequence[int]]) -> int:
    """Lab(x): каждый ниббл заменяется по T₀ или T₁, ветвь выбирается по данным.

    Селектор для ниббла j берётся из ниббла (j + 6) mod 12 -- с противоположной
    стороны слова, поэтому ни один ниббл не определяет собственное
    преобразование.

    Точка ошибки 10.4-5: все селекторы вычисляются из ИСХОДНОГО x, до замен.
    """
    y = 0
    for j in range(12):
        beta = (x >> SELECTOR_BITS[j]) & 1
        y |= T[beta][(x >> (4 * j)) & 0xF] << (4 * j)
    return y


# --------------------------------------------------------------------------
# Разделы 5 и 7. Разбиение ключа и расписание
# --------------------------------------------------------------------------

def split_key(K: int) -> Tuple[int, List[int]]:
    """K = K_L ‖ K₃ ‖ K₂ ‖ K₁ ‖ K₀ -> (K_L, [K₀, K₁, K₂, K₃])."""
    K &= (1 << KEY_BITS) - 1
    KL = (K >> 192) & ((1 << 64) - 1)
    S = [(K >> (W * j)) & M for j in range(4)]
    return KL, S


def key_schedule(K: int) -> List[int]:
    """Расписание ключей: 256-битный K -> 16 подключей по 48 бит."""
    KL, S = split_key(K)
    T = build_labyrinth(KL)

    subkeys: List[int] = []
    # Прогрев: шаги i = -4..-1 выполняются полностью, но подключ не выдаётся.
    # Без него лавина по мастер-ключу для k₀ падает до 17% вместо 50%.
    for i in range(-WARMUP, N):
        # (a) параллельно
        S = [apply_labyrinth(v, T) for v in S]

        # (b) ПОСЛЕДОВАТЕЛЬНО. Точка ошибки 10.4-1: при j = 3 берётся уже
        # обновлённое S₀.
        for j in range(4):
            S[j] = (S[j] + S[(j + 1) % 4]) & M

        # (c) параллельно. Точка ошибки 10.4-4: i mod 24 должно быть
        # неотрицательным (-4 mod 24 = 20 -> r = 45). В Python % уже такой.
        r = (2 * (i % 24) + 5) % W
        S = [rotl(v, r) for v in S]

        # (d) параллельно
        S = [apply_labyrinth(v, T) for v in S]

        # (e) выдача подключа
        if i >= 0:
            subkeys.append((S[i % 4] + round_constant(i)) & M)

    return subkeys


#: Величины сдвига r_i для шагов i = -4..15 (справочная таблица раздела 7).
SHIFTS: Tuple[int, ...] = tuple((2 * (i % 24) + 5) % W for i in range(-WARMUP, N))


# --------------------------------------------------------------------------
# Раздел 4. Шифрование и расшифровка
# --------------------------------------------------------------------------

def encrypt_block_with_subkeys(P: int, subkeys: Sequence[int],
                               rounds: int | None = None) -> int:
    """Шифрование блока на готовых подключах (для урезанных версий)."""
    if rounds is None:
        rounds = len(subkeys)
    L, R = (P >> W) & M, P & M
    for i in range(rounds):
        L, R = R, L ^ F(R, subkeys[i], i)
    return (L << W) | R


def decrypt_block_with_subkeys(C: int, subkeys: Sequence[int],
                               rounds: int | None = None) -> int:
    """Расшифровка блока на готовых подключах.

    Точка ошибки 10.4-7: подключи идут в обратном порядке, но номер раунда i
    внутри F остаётся тем же, что при шифровании -- он влияет на RC_i.
    """
    if rounds is None:
        rounds = len(subkeys)
    L, R = (C >> W) & M, C & M
    for i in reversed(range(rounds)):
        R, L = L, R ^ F(L, subkeys[i], i)
    return (L << W) | R


def encrypt_block(P: int, K: int, rounds: int = N) -> int:
    """Шифрует 96-битный блок P на 256-битном ключе K."""
    return encrypt_block_with_subkeys(P, key_schedule(K), rounds)


def decrypt_block(C: int, K: int, rounds: int = N) -> int:
    """Расшифровывает 96-битный блок C на 256-битном ключе K."""
    return decrypt_block_with_subkeys(C, key_schedule(K), rounds)


def encrypt_block_trace(P: int, K: int,
                        rounds: int = N) -> List[Tuple[int, int, int]]:
    """Пораундовая трассировка (формат раздела 8.5): [(F, L, R), ...]."""
    subkeys = key_schedule(K)
    L, R = (P >> W) & M, P & M
    trace = []
    for i in range(rounds):
        f = F(R, subkeys[i], i)
        L, R = R, L ^ f
        trace.append((f, L, R))
    return trace


# --------------------------------------------------------------------------
# Байтовые обёртки и режим CTR (раздел 10.3)
# --------------------------------------------------------------------------

def block_to_bytes(x: int) -> bytes:
    """96-битное целое -> 12 байт (big-endian)."""
    return (x & ((1 << BLOCK_BITS) - 1)).to_bytes(BLOCK_BYTES, "big")


def bytes_to_block(b: bytes) -> int:
    """12 байт (big-endian) -> 96-битное целое."""
    if len(b) != BLOCK_BYTES:
        raise ValueError(f"block must be {BLOCK_BYTES} bytes, got {len(b)}")
    return int.from_bytes(b, "big")


def key_from_bytes(b: bytes) -> int:
    """32 байта (big-endian) -> 256-битный ключ."""
    if len(b) != KEY_BYTES:
        raise ValueError(f"key must be {KEY_BYTES} bytes, got {len(b)}")
    return int.from_bytes(b, "big")


def key_to_bytes(K: int) -> bytes:
    """256-битный ключ -> 32 байта (big-endian)."""
    return (K & ((1 << KEY_BITS) - 1)).to_bytes(KEY_BYTES, "big")


class Dedalyan:
    """Контекст с предвычисленными подключами и таблицами лабиринта.

    Расписание ключей стоит около 40 вызовов F, поэтому при обработке более
    одного блока его следует вычислять один раз.
    """

    __slots__ = ("subkeys", "tables", "rounds")

    def __init__(self, key: int | bytes, rounds: int = N) -> None:
        if isinstance(key, (bytes, bytearray, memoryview)):
            key = key_from_bytes(bytes(key))
        if not 1 <= rounds <= N:
            raise ValueError(f"rounds must be in 1..{N}, got {rounds}")
        self.rounds = rounds
        self.subkeys = key_schedule(key)
        self.tables = build_labyrinth(split_key(key)[0])

    def encrypt_block(self, P: int) -> int:
        return encrypt_block_with_subkeys(P, self.subkeys, self.rounds)

    def decrypt_block(self, C: int) -> int:
        return decrypt_block_with_subkeys(C, self.subkeys, self.rounds)

    def encrypt_bytes(self, block: bytes) -> bytes:
        return block_to_bytes(self.encrypt_block(bytes_to_block(block)))

    def decrypt_bytes(self, block: bytes) -> bytes:
        return block_to_bytes(self.decrypt_block(bytes_to_block(block)))

    # -- CTR --------------------------------------------------------------

    def keystream(self, counter: int, nblocks: int) -> Iterator[bytes]:
        """Генератор блоков гаммы. Счётчик 96-битный, инкремент mod 2^96."""
        mask = (1 << BLOCK_BITS) - 1
        counter &= mask
        for _ in range(nblocks):
            yield block_to_bytes(self.encrypt_block(counter))
            counter = (counter + 1) & mask

    def ctr(self, data: bytes, counter: int = 0) -> bytes:
        """Режим CTR. Самообратен: ctr(ctr(x)) == x при том же счётчике."""
        mask = (1 << BLOCK_BITS) - 1
        counter &= mask
        out = bytearray(len(data))
        for off in range(0, len(data), BLOCK_BYTES):
            ks = block_to_bytes(self.encrypt_block(counter))
            counter = (counter + 1) & mask
            chunk = data[off:off + BLOCK_BYTES]
            out[off:off + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, ks))
        return bytes(out)


def ctr_keystream(key: int | bytes, nbytes: int, counter: int = 0,
                  rounds: int = N) -> bytes:
    """Гамма длиной nbytes байт в режиме CTR."""
    ctx = Dedalyan(key, rounds)
    nblocks = (nbytes + BLOCK_BYTES - 1) // BLOCK_BYTES
    return b"".join(ctx.keystream(counter, nblocks))[:nbytes]


def ctr_crypt(key: int | bytes, data: bytes, counter: int = 0,
              rounds: int = N) -> bytes:
    """Шифрование/расшифровка произвольных данных в режиме CTR."""
    return Dedalyan(key, rounds).ctr(data, counter)


if __name__ == "__main__":  # быстрая самопроверка
    K3 = int.from_bytes(bytes(range(32)), "big")
    assert encrypt_block(0, 0) == 0x70A4CEAA4A6737FB294A0EDF
    assert encrypt_block(0x0123456789ABCDEF01234567, K3) == 0x9B631FE623F15016CDBA801E
    assert decrypt_block(encrypt_block(12345, K3), K3) == 12345
    print("dedalyan.py: self-check OK")
