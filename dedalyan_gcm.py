"""Dedalyan-GCM-96 — аутентифицированное шифрование на базе Dedalyan-96/256.

ЭТО НЕ NIST SP 800-38D. Настоящий GCM определён для 128-битного блока: его
GHASH живёт в GF(2^128), счётчик собирается как 96-битный IV и 32-битный
счётчик, а тег имеет длину блока. У Dedalyan блок 96 бит, поэтому прямое
применение невозможно, и здесь построена адаптация той же схемы на GF(2^96).
Она корректна по построению, но это ещё одна непроверенная конструкция поверх
непроверенного шифра — см. раздел 0 спецификации.

Поле. GF(2^96) по модулю неприводимого многочлена

    f(x) = x^96 + x^10 + x^9 + x^6 + 1

Неприводимость проверена вычислением (тест Рабина), а сам тест проверен на
эталонах, включая многочлены AES и GCM. Триномов степени 96 над GF(2) не
существует, поэтому взят пентаном минимального веса.

Соглашение о битах взято из GCM: самый старший бит блока — коэффициент при
x^0, самый младший — при x^95. Из-за этого умножение на x есть сдвиг ВПРАВО.
Соглашение сохранено намеренно: тот, кто знает GCM, узнает конструкцию.

Схема::

    H   = E_K(0^96)                            подключ хеша
    J0  = nonce (8 байт) || 0x00000001         начальный блок счётчика
    C   = CTR_{J0+1}(P)
    tag = GHASH_H(A ‖ pad ‖ C ‖ pad ‖ len(A) ‖ len(C)) ⊕ E_K(J0)

Длины в финальном блоке — по 48 бит каждая (в GCM по 64), чтобы блок длин
занимал ровно один 96-битный блок.

Ограничения, вытекающие из размеров:

* nonce 64 бита фиксирован. Переменная длина IV, как в GCM, не поддержана
  намеренно: меньше путей — меньше способов ошибиться.
* счётчик блоков 32 бита, значит одно сообщение не длиннее
  (2^32 − 2) · 12 байт ≈ 48 ГиБ. Для файлов больше — кадрированный формат
  в ``dedalyan_file.py``.
* пара (ключ, nonce) не должна повторяться НИКОГДА. Повтор в CTR отдаёт XOR
  открытых текстов, а в GCM дополнительно вскрывает H и позволяет подделывать
  теги. Здесь nonce обязателен явный: генерировать его молча внутри — значит
  прятать самое опасное место схемы.
* блок 96 бит: граница дней рождения 2^48 блоков (~3.4 ПиБ) на один ключ.

Использование::

    from dedalyan_gcm import seal, open_, AuthenticationError

    sealed = seal(key32, nonce8, b"payload", aad=b"header")
    try:
        plain = open_(key32, nonce8, sealed, aad=b"header")
    except AuthenticationError:
        ...  # тег не сошёлся: подделка или не тот ключ
"""

from __future__ import annotations

import hmac
import struct
from typing import Optional, Tuple

import dedalyan as D

__all__ = [
    "AuthenticationError", "BLOCK_BYTES", "NONCE_BYTES", "TAG_BYTES",
    "MAX_MESSAGE_BYTES", "R", "POLY_LOW",
    "gf_mul", "ghash", "seal", "open_", "GcmContext",
]

BLOCK_BITS = 96
BLOCK_BYTES = 12
NONCE_BYTES = 8
COUNTER_BYTES = BLOCK_BYTES - NONCE_BYTES        # 4
TAG_BYTES = 12
KEY_BYTES = D.KEY_BYTES

#: Одно сообщение: счётчик 32-битный, значения 0 и 1 заняты под J0.
MAX_MESSAGE_BYTES = ((1 << (8 * COUNTER_BYTES)) - 2) * BLOCK_BYTES

MASK96 = (1 << BLOCK_BITS) - 1

#: Младшие члены f(x): x^10 + x^9 + x^6 + 1.
POLY_LOW = (1 << 10) | (1 << 9) | (1 << 6) | 1

#: Константа редукции в отражённом представлении GCM.
#: Коэффициент при x^j лежит в бите (95 − j), поэтому младшие члены
#: многочлена оказываются в старших битах блока.
R = 0
for _j in (10, 9, 6, 0):
    R |= 1 << (BLOCK_BITS - 1 - _j)
del _j
assert R == 0x826000000000000000000000, f"{R:#026x}"


class AuthenticationError(Exception):
    """Тег не сошёлся: неверный ключ, неверный nonce/AAD или подделка."""


# --------------------------------------------------------------------------
# Поле GF(2^96)
# --------------------------------------------------------------------------

def gf_mul(x: int, y: int) -> int:
    """Умножение в GF(2^96) в соглашении GCM (умножение на x — сдвиг вправо)."""
    z = 0
    v = y & MASK96
    for i in range(BLOCK_BITS):
        if (x >> (BLOCK_BITS - 1 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z & MASK96


def _b2i(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _i2b(x: int) -> bytes:
    return (x & MASK96).to_bytes(BLOCK_BYTES, "big")


def ghash(h: int, data: bytes) -> int:
    """GHASH_H(data). Длина data обязана быть кратна размеру блока."""
    if len(data) % BLOCK_BYTES:
        raise ValueError("ghash input must be block-aligned")
    y = 0
    for off in range(0, len(data), BLOCK_BYTES):
        y = gf_mul(y ^ _b2i(data[off:off + BLOCK_BYTES]), h)
    return y


def _pad(data: bytes) -> bytes:
    """Дополнение нулями до границы блока."""
    rem = len(data) % BLOCK_BYTES
    return data + (b"\x00" * (BLOCK_BYTES - rem) if rem else b"")


def _len_block(aad_len: int, ct_len: int) -> bytes:
    """Финальный блок GHASH: две длины в БИТАХ по 48 бит."""
    limit = 1 << 48
    if aad_len * 8 >= limit or ct_len * 8 >= limit:
        raise ValueError("length field overflow (48-bit bit-lengths)")
    return ((aad_len * 8) << 48 | (ct_len * 8)).to_bytes(BLOCK_BYTES, "big")


# --------------------------------------------------------------------------
# Схема
# --------------------------------------------------------------------------

def _j0(nonce: bytes) -> int:
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"nonce must be {NONCE_BYTES} bytes, got {len(nonce)}")
    return _b2i(nonce + b"\x00" * (COUNTER_BYTES - 1) + b"\x01")


class GcmContext:
    """Контекст с предвычисленными подключами шифра и подключом хеша H.

    Расписание ключей и вычисление H стоят заметно дороже одного блока,
    поэтому при обработке нескольких сообщений на одном ключе контекст
    следует создавать один раз.
    """

    __slots__ = ("_ctx", "_h", "_backend", "_cctx", "_gctx")

    def __init__(self, key: bytes, force_python: bool = False) -> None:
        if len(key) != KEY_BYTES:
            raise ValueError(f"key must be {KEY_BYTES} bytes, got {len(key)}")
        self._backend = None
        self._cctx = None
        self._gctx = None
        if not force_python:
            try:
                from dedalyan_c import backend
                if backend.available:
                    self._backend = backend
                    self._cctx = backend.new_ctx(key)
                    # Полный GCM-контекст с таблицами GHASH: побитовое
                    # умножение на Python даёт около 400 КБ/с, что делает
                    # шифрование файлов неосуществимым.
                    self._gctx = backend.gcm_new(key)
            except Exception:
                self._backend = self._cctx = self._gctx = None
        self._ctx = D.Dedalyan(key)
        self._h = self._encrypt_block(0)

    # -- примитивы --------------------------------------------------------

    def _encrypt_block(self, block: int) -> int:
        if self._backend is not None:
            return self._backend.encrypt_block(self._cctx, block)
        return self._ctx.encrypt_block(block)

    def _ctr(self, start: int, data: bytes) -> bytes:
        """CTR начиная со счётчика start. Инкремент — только младшие 32 бита."""
        if self._backend is not None:
            return self._backend.ctr(
                self._cctx, start.to_bytes(BLOCK_BYTES, "big"), data,
                len(data), D.N)
        return self._ctx.ctr(data, start)

    @property
    def h(self) -> int:
        """Подключ хеша H = E_K(0^96)."""
        return self._h

    # -- AEAD -------------------------------------------------------------

    def _tag(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        s = ghash(self._h,
                  _pad(aad) + _pad(ciphertext) + _len_block(len(aad),
                                                            len(ciphertext)))
        return _i2b(s ^ self._encrypt_block(_j0(nonce)))

    def seal(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Шифрует и аутентифицирует. Возвращает ciphertext ‖ tag."""
        if len(nonce) != NONCE_BYTES:
            raise ValueError(f"nonce must be {NONCE_BYTES} bytes")
        if len(plaintext) > MAX_MESSAGE_BYTES:
            raise ValueError(
                f"message exceeds {MAX_MESSAGE_BYTES} bytes; the 32-bit block "
                f"counter would wrap into the nonce and repeat keystream")
        if self._gctx is not None:
            return self._backend.gcm_seal(self._gctx, nonce, plaintext, aad)
        ciphertext = self._ctr(_j0(nonce) + 1, plaintext)
        return ciphertext + self._tag(nonce, ciphertext, aad)

    def open_(self, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
        """Проверяет тег и расшифровывает.

        Тег проверяется ДО расшифровки: неаутентифицированные данные не
        обрабатываются вообще.
        """
        if len(nonce) != NONCE_BYTES:
            raise ValueError(f"nonce must be {NONCE_BYTES} bytes")
        if len(sealed) < TAG_BYTES:
            raise AuthenticationError("input shorter than the tag")
        if self._gctx is not None:
            try:
                return self._backend.gcm_open(self._gctx, nonce, sealed, aad)
            except ValueError as exc:
                raise AuthenticationError(
                    "authentication failed: wrong key/nonce/AAD, or the "
                    "ciphertext was modified") from exc
        ciphertext, tag = sealed[:-TAG_BYTES], sealed[-TAG_BYTES:]
        expected = self._tag(nonce, ciphertext, aad)
        # compare_digest, а не ==: обычное сравнение выходит на первом
        # несовпавшем байте, и время ответа выдаёт, сколько байт угадано.
        if not hmac.compare_digest(tag, expected):
            raise AuthenticationError(
                "authentication failed: wrong key/nonce/AAD, or the "
                "ciphertext was modified")
        return self._ctr(_j0(nonce) + 1, ciphertext)


# --------------------------------------------------------------------------
# Функции одного вызова
# --------------------------------------------------------------------------

def seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Однократное шифрование. Для нескольких сообщений берите GcmContext."""
    return GcmContext(key).seal(nonce, plaintext, aad)


def open_(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """Однократная расшифровка. Бросает AuthenticationError."""
    return GcmContext(key).open_(nonce, sealed, aad)


if __name__ == "__main__":
    import os
    k = bytes(range(32))
    n = bytes(range(8))
    pt = b"Dedalyan-GCM-96 self-check. " * 5
    ad = b"header"

    ct = seal(k, n, pt, ad)
    assert open_(k, n, ct, ad) == pt, "roundtrip failed"

    for name, mangle in (
        ("ciphertext bit", lambda b: bytes([b[0] ^ 1]) + b[1:]),
        ("tag bit", lambda b: b[:-1] + bytes([b[-1] ^ 1])),
    ):
        try:
            open_(k, n, mangle(ct), ad)
            raise SystemExit(f"FAIL: tampered {name} was accepted")
        except AuthenticationError:
            pass
    try:
        open_(k, n, ct, b"other")
        raise SystemExit("FAIL: wrong AAD was accepted")
    except AuthenticationError:
        pass

    print("dedalyan_gcm.py: self-check OK")
    print(f"  H = {GcmContext(k).h:024x}")
    print(f"  ct||tag ({len(ct)} B) = {ct[:24].hex()}...")
