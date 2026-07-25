"""Мост к C-реализации Dedalyan через ctypes.

Быстрый путь для тестов и криптоанализа: чистый Python даёт порядка 10^4
блоков в секунду, C -- порядка 10^7. Атаки на 2^28 и больше без него
неосуществимы.

Использование::

    from dedalyan_c import backend
    if backend.available:
        ctx = backend.new_ctx(key_bytes)
        ...

Если библиотека не собрана, ``backend.available`` равно False, и вызывающий
код должен откатиться на ``dedalyan.py``. Собрать библиотеку::

    powershell -ExecutionPolicy Bypass -File build.ps1
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import (POINTER, c_char_p, c_int, c_size_t, c_uint8, c_uint32,
                    c_uint64, c_void_p)
from pathlib import Path
from typing import Optional, Sequence

try:
    import numpy as _np
except ImportError:  # numpy не обязателен, но с ним удобнее
    _np = None

__all__ = ["backend", "CBackend", "Block", "Ctx", "library_path"]

ROUNDS = 16
MASK = (1 << 48) - 1


# --------------------------------------------------------------------------
# Поиск библиотеки
# --------------------------------------------------------------------------

def library_path() -> Optional[Path]:
    """Путь к собранной библиотеке или None."""
    # Явно заданный путь возвращается как есть, даже если файла нет: тихий
    # откат на другую библиотеку хуже громкой ошибки -- при опечатке в
    # переменной окружения загрузился бы не тот бинарник.
    env = os.environ.get("DEDALYAN_DLL")
    if env:
        return Path(env)

    root = Path(__file__).resolve().parent
    names = ["dedalyan.dll"] if sys.platform == "win32" else \
            ["libdedalyan.so", "libdedalyan.dylib", "dedalyan.so"]
    for d in (root / "build", root, root / "c"):
        for n in names:
            p = d / n
            if p.is_file():
                return p
    return None


# --------------------------------------------------------------------------
# Структуры
# --------------------------------------------------------------------------

class Block(ctypes.Structure):
    """Половины блока: l -- старшие 48 бит, r -- младшие."""
    _fields_ = [("l", c_uint64), ("r", c_uint64)]

    @classmethod
    def from_int(cls, x: int) -> "Block":
        return cls((x >> 48) & MASK, x & MASK)

    def to_int(self) -> int:
        return ((self.l & MASK) << 48) | (self.r & MASK)


class Ctx(ctypes.Structure):
    """dedalyan_ctx: подключи + таблицы лабиринта."""
    _fields_ = [("rk", c_uint64 * 16), ("T", (c_uint8 * 16) * 2)]


U64P = POINTER(c_uint64)
U32P = POINTER(c_uint32)
U8P = POINTER(c_uint8)


# --------------------------------------------------------------------------
# Бэкенд
# --------------------------------------------------------------------------

class CBackend:
    """Обёртка над dedalyan.dll. Создаётся один раз при импорте."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path if path is not None else library_path()
        self.lib = None
        self.available = False
        self.error: Optional[str] = None
        if self.path is None:
            self.error = ("dedalyan.dll not built -- run: "
                          "powershell -ExecutionPolicy Bypass -File build.ps1")
            return
        try:
            self.lib = ctypes.CDLL(str(self.path))
            self._bind()
            self.available = True
        except OSError as exc:  # pragma: no cover
            self.error = f"failed to load {self.path}: {exc}"

    # -- прототипы --------------------------------------------------------

    def _bind(self) -> None:
        L = self.lib
        sig = [
            # шифр
            ("dedalyan_key_setup", None, [POINTER(Ctx), U8P]),
            ("dedalyan_ctx_wipe", None, [POINTER(Ctx)]),
            ("dedalyan_rc", c_uint64, [ctypes.c_uint]),
            ("dedalyan_rotl", c_uint64, [c_uint64, ctypes.c_uint]),
            ("dedalyan_rotr", c_uint64, [c_uint64, ctypes.c_uint]),
            ("dedalyan_f", c_uint64, [c_uint64, c_uint64, ctypes.c_uint]),
            ("dedalyan_build_labyrinth", None, [c_uint64, U8P]),
            ("dedalyan_apply_labyrinth", c_uint64, [c_uint64, U8P]),
            ("dedalyan_key_schedule", None, [U8P, U64P]),
            ("dedalyan_encrypt", Block, [POINTER(Ctx), Block]),
            ("dedalyan_decrypt", Block, [POINTER(Ctx), Block]),
            ("dedalyan_encrypt_r", Block, [POINTER(Ctx), Block, ctypes.c_uint]),
            ("dedalyan_decrypt_r", Block, [POINTER(Ctx), Block, ctypes.c_uint]),
            ("dedalyan_encrypt_bytes", None, [POINTER(Ctx), U8P, U8P]),
            ("dedalyan_decrypt_bytes", None, [POINTER(Ctx), U8P, U8P]),
            ("dedalyan_encrypt_blocks", None,
             [POINTER(Ctx), U64P, c_size_t, ctypes.c_uint]),
            ("dedalyan_decrypt_blocks", None,
             [POINTER(Ctx), U64P, c_size_t, ctypes.c_uint]),
            ("dedalyan_ctr", None,
             [POINTER(Ctx), U8P, U8P, U8P, c_size_t, ctypes.c_uint]),
            ("dedalyan_encrypt_trace", None,
             [POINTER(Ctx), Block, ctypes.c_uint, U64P, U64P, U64P]),
            ("dedalyan_version", c_char_p, []),
            # ядра анализа
            ("ded_k_splitmix64", c_uint64, [U64P]),
            ("ded_k_diff_bitcount", None,
             [POINTER(Ctx), ctypes.c_uint, c_uint64, c_uint64,
              c_size_t, c_uint64, U64P]),
            ("ded_k_diff_nibble_seen", None,
             [POINTER(Ctx), ctypes.c_uint, c_uint64, c_uint64,
              c_size_t, c_uint64, U8P]),
            ("ded_k_diff_exact", c_uint64,
             [POINTER(Ctx), ctypes.c_uint, c_uint64, c_uint64,
              c_uint64, c_uint64, c_size_t, c_uint64]),
            ("ded_k_diffusion_cover", None,
             [POINTER(Ctx), ctypes.c_uint, c_size_t, c_uint64, U64P]),
            ("ded_k_diffusion_count", None,
             [POINTER(Ctx), ctypes.c_uint, c_size_t, c_uint64, U32P]),
            ("ded_k_avalanche", None,
             [POINTER(Ctx), ctypes.c_uint, c_size_t, c_uint64, U64P, U64P]),
            ("ded_k_linear_pairs", None,
             [POINTER(Ctx), ctypes.c_uint, U64P, c_size_t,
              c_size_t, c_uint64, U64P]),
            ("ded_k_boomerang", c_uint64,
             [POINTER(Ctx), ctypes.c_uint, c_uint64, c_uint64,
              c_uint64, c_uint64, c_size_t, c_uint64]),
            ("ded_k_integral_sum", None,
             [POINTER(Ctx), ctypes.c_uint, c_uint64, c_uint64, U8P,
              ctypes.c_uint, U64P, U64P]),
            ("ded_k_key_avalanche", None,
             [ctypes.c_uint, c_size_t, c_uint64, U32P]),
            ("ded_k_subkey_avalanche", None, [c_size_t, c_uint64, U64P, U64P]),
            ("ded_k_relkey_bitcount", None,
             [ctypes.c_uint, U8P, c_size_t, c_uint64, U64P]),
            ("ded_k_key_fingerprint", None,
             [ctypes.c_uint, c_uint64, c_uint64, c_size_t, c_uint64, U64P]),
            ("ded_k_subkey_dump", None, [c_size_t, c_uint64, U64P]),
            ("ded_k_labyrinth_fixpoints", None, [c_size_t, c_uint64, U8P]),
            ("ded_k_rotational", c_uint64,
             [ctypes.c_uint, ctypes.c_uint, c_int, c_size_t, c_uint64]),
            ("ded_k_ctr_stream", None,
             [POINTER(Ctx), ctypes.c_uint, c_uint64, c_uint64, U8P, c_size_t]),
            ("ded_k_random_ecb", None,
             [POINTER(Ctx), ctypes.c_uint, c_size_t, c_uint64, U64P]),
        ]
        for name, restype, argtypes in sig:
            fn = getattr(L, name)
            fn.restype = restype
            fn.argtypes = argtypes

    # -- удобные обёртки ---------------------------------------------------

    def _require(self) -> None:
        if not self.available:
            raise RuntimeError(self.error or "C backend unavailable")

    def new_ctx(self, key: bytes) -> Ctx:
        """Контекст ключа из 32 байт (big-endian)."""
        self._require()
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        ctx = Ctx()
        buf = (c_uint8 * 32).from_buffer_copy(key)
        self.lib.dedalyan_key_setup(ctypes.byref(ctx), buf)
        return ctx

    def version(self) -> str:
        self._require()
        return self.lib.dedalyan_version().decode()

    def key_schedule(self, key: bytes) -> list:
        self._require()
        buf = (c_uint8 * 32).from_buffer_copy(key)
        out = (c_uint64 * 16)()
        self.lib.dedalyan_key_schedule(buf, out)
        return list(out)

    def build_labyrinth(self, kl: int):
        self._require()
        T = ((c_uint8 * 16) * 2)()
        self.lib.dedalyan_build_labyrinth(c_uint64(kl),
                                          ctypes.cast(T, U8P))
        return [list(T[0]), list(T[1])]

    def apply_labyrinth(self, x: int, T) -> int:
        self._require()
        buf = (c_uint8 * 32)()
        for i in range(16):
            buf[i] = T[0][i]
            buf[16 + i] = T[1][i]
        return int(self.lib.dedalyan_apply_labyrinth(c_uint64(x), buf))

    def encrypt_block(self, ctx: Ctx, p: int, rounds: int = ROUNDS) -> int:
        self._require()
        b = self.lib.dedalyan_encrypt_r(ctypes.byref(ctx), Block.from_int(p),
                                        rounds)
        return b.to_int()

    def decrypt_block(self, ctx: Ctx, c: int, rounds: int = ROUNDS) -> int:
        self._require()
        b = self.lib.dedalyan_decrypt_r(ctypes.byref(ctx), Block.from_int(c),
                                        rounds)
        return b.to_int()

    def encrypt_many(self, ctx: Ctx, lr, rounds: int = ROUNDS):
        """lr -- numpy-массив uint64 формы (n, 2) [l, r]. Обработка на месте."""
        self._require()
        if _np is None:
            raise RuntimeError("numpy required for encrypt_many")
        arr = _np.ascontiguousarray(lr, dtype=_np.uint64)
        n = arr.shape[0]
        self.lib.dedalyan_encrypt_blocks(
            ctypes.byref(ctx), arr.ctypes.data_as(U64P), n, rounds)
        return arr

    def decrypt_many(self, ctx: Ctx, lr, rounds: int = ROUNDS):
        self._require()
        if _np is None:
            raise RuntimeError("numpy required for decrypt_many")
        arr = _np.ascontiguousarray(lr, dtype=_np.uint64)
        n = arr.shape[0]
        self.lib.dedalyan_decrypt_blocks(
            ctypes.byref(ctx), arr.ctypes.data_as(U64P), n, rounds)
        return arr

    def ctr(self, ctx: Ctx, counter: bytes, data: Optional[bytes],
            length: Optional[int] = None, rounds: int = ROUNDS) -> bytes:
        self._require()
        if length is None:
            if data is None:
                raise ValueError("length required when data is None")
            length = len(data)
        ctr_buf = (c_uint8 * 12).from_buffer_copy(counter)
        out = (c_uint8 * length)()
        in_ptr = ((c_uint8 * len(data)).from_buffer_copy(data)
                  if data is not None else ctypes.cast(None, U8P))
        self.lib.dedalyan_ctr(ctypes.byref(ctx), ctr_buf, in_ptr, out,
                              length, rounds)
        return bytes(out)

    def trace(self, ctx: Ctx, p: int, rounds: int = ROUNDS):
        self._require()
        f = (c_uint64 * rounds)()
        l = (c_uint64 * rounds)()
        r = (c_uint64 * rounds)()
        self.lib.dedalyan_encrypt_trace(ctypes.byref(ctx), Block.from_int(p),
                                        rounds, f, l, r)
        return list(zip(list(f), list(l), list(r)))

    # -- ядра анализа ------------------------------------------------------

    def diff_bitcount(self, ctx: Ctx, rounds: int, dl: int, dr: int,
                      n: int, seed: int):
        self._require()
        out = _np.zeros(96, dtype=_np.uint64)
        self.lib.ded_k_diff_bitcount(ctypes.byref(ctx), rounds, dl, dr, n,
                                     seed, out.ctypes.data_as(U64P))
        return out

    def diff_nibble_seen(self, ctx: Ctx, rounds: int, dl: int, dr: int,
                         n: int, seed: int):
        self._require()
        out = _np.zeros(24 * 16, dtype=_np.uint8)
        self.lib.ded_k_diff_nibble_seen(ctypes.byref(ctx), rounds, dl, dr, n,
                                        seed, out.ctypes.data_as(U8P))
        return out.reshape(24, 16)

    def diff_exact(self, ctx: Ctx, rounds: int, dl: int, dr: int,
                   ol: int, orr: int, n: int, seed: int) -> int:
        self._require()
        return int(self.lib.ded_k_diff_exact(ctypes.byref(ctx), rounds,
                                             dl, dr, ol, orr, n, seed))

    def diffusion_cover(self, ctx: Ctx, rounds: int, n: int, seed: int):
        self._require()
        out = _np.zeros(192, dtype=_np.uint64)
        self.lib.ded_k_diffusion_cover(ctypes.byref(ctx), rounds, n, seed,
                                       out.ctypes.data_as(U64P))
        return out.reshape(96, 2)

    def diffusion_count(self, ctx: Ctx, rounds: int, n: int, seed: int):
        self._require()
        out = _np.zeros(96 * 96, dtype=_np.uint32)
        self.lib.ded_k_diffusion_count(ctypes.byref(ctx), rounds, n, seed,
                                       out.ctypes.data_as(U32P))
        return out.reshape(96, 96)

    def avalanche(self, ctx: Ctx, rounds: int, n: int, seed: int):
        self._require()
        s1 = c_uint64(0)
        s2 = c_uint64(0)
        self.lib.ded_k_avalanche(ctypes.byref(ctx), rounds, n, seed,
                                 ctypes.byref(s1), ctypes.byref(s2))
        return int(s1.value), int(s2.value)

    def linear_pairs(self, ctx: Ctx, rounds: int, masks, n: int, seed: int):
        """masks -- массив формы (npairs, 4): (in_l, in_r, out_l, out_r)."""
        self._require()
        arr = _np.ascontiguousarray(masks, dtype=_np.uint64)
        npairs = arr.shape[0]
        out = _np.zeros(npairs, dtype=_np.uint64)
        self.lib.ded_k_linear_pairs(ctypes.byref(ctx), rounds,
                                    arr.ctypes.data_as(U64P), npairs, n, seed,
                                    out.ctypes.data_as(U64P))
        return out

    def boomerang(self, ctx: Ctx, rounds: int, al: int, ar: int,
                  dl: int, dr: int, n: int, seed: int) -> int:
        self._require()
        return int(self.lib.ded_k_boomerang(ctypes.byref(ctx), rounds,
                                            al, ar, dl, dr, n, seed))

    def integral_sum(self, ctx: Ctx, rounds: int, base_l: int, base_r: int,
                     active_bits: Sequence[int]):
        self._require()
        k = len(active_bits)
        buf = (c_uint8 * max(k, 1))(*[int(b) for b in active_bits])
        sl = c_uint64(0)
        sr = c_uint64(0)
        self.lib.ded_k_integral_sum(ctypes.byref(ctx), rounds, base_l, base_r,
                                    buf, k, ctypes.byref(sl), ctypes.byref(sr))
        return int(sl.value), int(sr.value)

    def key_avalanche(self, rounds: int, n: int, seed: int):
        self._require()
        out = _np.zeros(256 * 96, dtype=_np.uint32)
        self.lib.ded_k_key_avalanche(rounds, n, seed, out.ctypes.data_as(U32P))
        return out.reshape(256, 96)

    def subkey_avalanche(self, n: int, seed: int):
        self._require()
        s1 = _np.zeros(16, dtype=_np.uint64)
        s2 = _np.zeros(16, dtype=_np.uint64)
        self.lib.ded_k_subkey_avalanche(n, seed, s1.ctypes.data_as(U64P),
                                        s2.ctypes.data_as(U64P))
        return s1, s2

    def relkey_bitcount(self, rounds: int, dk: bytes, n: int, seed: int):
        self._require()
        buf = (c_uint8 * 32).from_buffer_copy(dk)
        out = _np.zeros(96, dtype=_np.uint64)
        self.lib.ded_k_relkey_bitcount(rounds, buf, n, seed,
                                       out.ctypes.data_as(U64P))
        return out

    def key_fingerprint(self, rounds: int, pl: int, pr: int, n: int, seed: int):
        self._require()
        out = _np.zeros((n, 2), dtype=_np.uint64)
        self.lib.ded_k_key_fingerprint(rounds, pl, pr, n, seed,
                                       out.ctypes.data_as(U64P))
        return out

    def subkey_dump(self, n: int, seed: int):
        self._require()
        out = _np.zeros((n, 16), dtype=_np.uint64)
        self.lib.ded_k_subkey_dump(n, seed, out.ctypes.data_as(U64P))
        return out

    def labyrinth_fixpoints(self, n: int, seed: int):
        self._require()
        out = _np.zeros(n, dtype=_np.uint8)
        self.lib.ded_k_labyrinth_fixpoints(n, seed, out.ctypes.data_as(U8P))
        return out

    def rotational(self, rounds: int, rot: int, key_rot: bool,
                   n: int, seed: int) -> int:
        self._require()
        return int(self.lib.ded_k_rotational(rounds, rot, 1 if key_rot else 0,
                                             n, seed))

    def ctr_stream(self, ctx: Ctx, rounds: int, ctr_hi: int, ctr_lo: int,
                   length: int) -> bytes:
        self._require()
        out = _np.zeros(length, dtype=_np.uint8)
        self.lib.ded_k_ctr_stream(ctypes.byref(ctx), rounds, ctr_hi, ctr_lo,
                                  out.ctypes.data_as(U8P), length)
        return out.tobytes()

    def random_ecb(self, ctx: Ctx, rounds: int, n: int, seed: int):
        self._require()
        out = _np.zeros((n, 2), dtype=_np.uint64)
        self.lib.ded_k_random_ecb(ctypes.byref(ctx), rounds, n, seed,
                                  out.ctypes.data_as(U64P))
        return out


#: Единственный экземпляр, создаётся при импорте модуля.
backend = CBackend()


if __name__ == "__main__":
    if not backend.available:
        print("C backend NOT available:", backend.error)
        raise SystemExit(1)
    print("C backend:", backend.version())
    print("library:  ", backend.path)
    ctx = backend.new_ctx(bytes(range(32)))
    got = backend.encrypt_block(ctx, 0x0123456789ABCDEF01234567)
    print("TV3:       %024x" % got)
    assert got == 0x9B631FE623F15016CDBA801E, "TV3 mismatch"
    print("self-check OK")
