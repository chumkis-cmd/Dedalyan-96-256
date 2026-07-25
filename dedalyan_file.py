"""Шифрование файлов Dedalyan: кадрированный формат поверх GCM-96.

Почему не «один GCM на весь файл». Тег можно проверить только после того,
как прочитан весь шифротекст. Значит либо файл целиком держится в памяти,
либо расшифрованные данные отдаются наружу до проверки тега — а это ровно
то, от чего аутентифицированное шифрование должно защищать. Поэтому файл
режется на кадры, каждый запечатывается отдельно, и потоковая расшифровка
отдаёт кадр только после успешной проверки его тега.

Кадрирование само по себе порождает три новые атаки, и каждая закрывается
явно, а не «само собой»:

* **перестановка кадров** — индекс кадра входит в AAD;
* **усечение файла** — последний кадр помечен флагом в AAD, поэтому обрубить
  хвост нельзя: разбор дойдёт до конца данных, не увидев флага;
* **склейка из разных файлов** — заголовок целиком входит в AAD каждого
  кадра, а он содержит соль и nonce, уникальные для файла.

Формат::

    magic        8  "DEDFILE1"
    version      1  = 1
    kdf          1  0 = raw key, 1 = Argon2id
    t_cost       1  \
    lanes        1   > параметры Argon2id, чтобы старые файлы читались
    mem_kib      4  /   после смены настроек по умолчанию
    chunk_size   4  размер кадра открытого текста, байт
    salt        16  соль Argon2id (нули при kdf = 0)
    file_id      8  случайный идентификатор файла
    ------------- заголовок 44 байта, входит в AAD каждого кадра
    кадр 0:  ciphertext[chunk_size] ‖ tag[12]
    кадр 1:  ...
    кадр N:  ciphertext[<= chunk_size] ‖ tag[12]

Nonce кадра i — это i в виде 8 байт big-endian. Это безопасно, потому что
ключ уникален для файла: он выводится Argon2id из случайной 16-байтовой соли
либо задан вызывающим и обязан быть одноразовым. Пара (ключ, nonce) при этом
не повторяется никогда, что для CTR и GCM критично.

AAD кадра i = header ‖ uint64(i) ‖ uint8(последний ли).

Накладные расходы: 44 байта заголовка плюс 12 байт на кадр. При кадре
256 КиБ это 0.005%.

ВНИМАНИЕ: шифр Dedalyan не проверялся независимыми криптоаналитиками, а
GCM-96 — адаптация, а не стандарт. Для реальных данных нужен age, GnuPG или
AES-GCM из проверенной библиотеки.
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path
from typing import BinaryIO, Callable, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dedalyan as D
from dedalyan_gcm import (AuthenticationError, GcmContext, NONCE_BYTES,
                          TAG_BYTES)

__all__ = [
    "MAGIC", "VERSION", "HEADER_BYTES", "DEFAULT_CHUNK",
    "AuthenticationError", "FileFormatError",
    "encrypt_stream", "decrypt_stream", "encrypt_file", "decrypt_file",
]

MAGIC = b"DEDFILE1"
VERSION = 1
KDF_RAW = 0
KDF_ARGON2ID = 1

SALT_BYTES = 16
FILE_ID_BYTES = 8
HEADER_BYTES = 8 + 1 + 1 + 1 + 1 + 4 + 4 + SALT_BYTES + FILE_ID_BYTES   # 44

DEFAULT_CHUNK = 256 * 1024
MIN_CHUNK = 1024
MAX_CHUNK = 64 * 1024 * 1024

# Параметры Argon2id по умолчанию: второй рекомендованный набор RFC 9106.
ARGON2_TIME = 3
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_LANES = 4

KEY_BYTES = D.KEY_BYTES


class FileFormatError(Exception):
    """Файл не является контейнером Dedalyan либо повреждён структурно."""


# --------------------------------------------------------------------------
# Заголовок
# --------------------------------------------------------------------------

_HDR = struct.Struct(">8sBBBBII16s8s")
assert _HDR.size == HEADER_BYTES, _HDR.size


def _pack_header(kdf: int, t: int, lanes: int, mem: int, chunk: int,
                 salt: bytes, file_id: bytes) -> bytes:
    return _HDR.pack(MAGIC, VERSION, kdf, t, lanes, mem, chunk, salt, file_id)


def _unpack_header(raw: bytes):
    if len(raw) != HEADER_BYTES:
        raise FileFormatError("truncated header")
    magic, ver, kdf, t, lanes, mem, chunk, salt, file_id = _HDR.unpack(raw)
    if magic != MAGIC:
        raise FileFormatError(
            "not a Dedalyan container (bad magic); "
            f"expected {MAGIC!r}, got {magic!r}")
    if ver != VERSION:
        raise FileFormatError(f"unsupported container version {ver}")
    if kdf not in (KDF_RAW, KDF_ARGON2ID):
        raise FileFormatError(f"unknown KDF id {kdf}")
    if not MIN_CHUNK <= chunk <= MAX_CHUNK:
        # Без этой проверки заявленный размер кадра в 4 ГиБ заставил бы
        # читателя выделить 4 ГиБ ещё до всякой аутентификации.
        raise FileFormatError(f"chunk size {chunk} out of range")
    return kdf, t, lanes, mem, chunk, salt, file_id


def _derive_key(password: str, salt: bytes, t: int, mem: int,
                lanes: int) -> bytes:
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        raise SystemExit("ERROR: argon2-cffi is required for password mode\n"
                         "       pip install argon2-cffi")
    return hash_secret_raw(secret=password.encode("utf-8"), salt=salt,
                           time_cost=t, memory_cost=mem, parallelism=lanes,
                           hash_len=KEY_BYTES, type=Type.ID)


def _aad(header: bytes, index: int, last: bool) -> bytes:
    return header + struct.pack(">QB", index, 1 if last else 0)


def _nonce(index: int) -> bytes:
    return index.to_bytes(NONCE_BYTES, "big")


# --------------------------------------------------------------------------
# Потоковое шифрование
# --------------------------------------------------------------------------

def encrypt_stream(src: BinaryIO, dst: BinaryIO, *,
                   password: Optional[str] = None,
                   key: Optional[bytes] = None,
                   chunk_size: int = DEFAULT_CHUNK,
                   time_cost: int = ARGON2_TIME,
                   memory_kib: int = ARGON2_MEMORY_KIB,
                   lanes: int = ARGON2_LANES,
                   progress: Optional[Callable[[int], None]] = None) -> int:
    """Шифрует поток. Возвращает число прочитанных байт открытого текста."""
    if (password is None) == (key is None):
        raise ValueError("provide exactly one of password= or key=")
    if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
        raise ValueError(f"chunk_size must be in {MIN_CHUNK}..{MAX_CHUNK}")

    if password is not None:
        salt = os.urandom(SALT_BYTES)
        file_key = _derive_key(password, salt, time_cost, memory_kib, lanes)
        kdf = KDF_ARGON2ID
    else:
        if len(key) != KEY_BYTES:
            raise ValueError(f"key must be {KEY_BYTES} bytes")
        salt = bytes(SALT_BYTES)
        file_key = key
        kdf, time_cost, memory_kib, lanes = KDF_RAW, 0, 0, 0

    file_id = os.urandom(FILE_ID_BYTES)
    header = _pack_header(kdf, time_cost, lanes, memory_kib, chunk_size,
                          salt, file_id)
    dst.write(header)

    ctx = GcmContext(file_key)
    index = 0
    total = 0
    pending = src.read(chunk_size)
    while True:
        nxt = src.read(chunk_size)
        last = not nxt
        dst.write(ctx.seal(_nonce(index), pending, _aad(header, index, last)))
        total += len(pending)
        if progress:
            progress(total)
        index += 1
        if last:
            break
        pending = nxt
        # Индекс кадра занимает 64 бита nonce, переполниться не может
        # раньше, чем кончится дисковое пространство планеты.
    return total


def decrypt_stream(src: BinaryIO, dst: BinaryIO, *,
                   password: Optional[str] = None,
                   key: Optional[bytes] = None,
                   progress: Optional[Callable[[int], None]] = None) -> int:
    """Расшифровывает поток. Кадр отдаётся только после проверки его тега."""
    if (password is None) == (key is None):
        raise ValueError("provide exactly one of password= or key=")

    header = src.read(HEADER_BYTES)
    kdf, t, lanes, mem, chunk, salt, _fid = _unpack_header(header)

    if kdf == KDF_ARGON2ID:
        if password is None:
            raise ValueError("this container is password-protected; "
                             "pass password=")
        file_key = _derive_key(password, salt, t, mem, lanes)
    else:
        if key is None:
            raise ValueError("this container uses a raw key; pass key=")
        if len(key) != KEY_BYTES:
            raise ValueError(f"key must be {KEY_BYTES} bytes")
        file_key = key

    ctx = GcmContext(file_key)
    index = 0
    total = 0
    frame = chunk + TAG_BYTES

    while True:
        blob = src.read(frame)
        if not blob:
            # Данные кончились, а кадра с флагом «последний» не было:
            # файл усечён. Это именно то, что флаг и должен ловить.
            raise AuthenticationError(
                f"truncated container: no final frame (stopped at frame "
                f"{index})")
        if len(blob) < TAG_BYTES:
            raise AuthenticationError("truncated frame: shorter than the tag")

        # Кадр полного размера может оказаться и последним, поэтому пробуем
        # оба варианта флага. Порядок важен только для скорости.
        is_full = len(blob) == frame
        for last in ((False, True) if is_full else (True,)):
            try:
                plain = ctx.open_(_nonce(index), blob,
                                  _aad(header, index, last))
                break
            except AuthenticationError:
                plain = None
        if plain is None:
            raise AuthenticationError(
                f"authentication failed on frame {index}: wrong password/key, "
                f"or the container was modified")

        dst.write(plain)
        total += len(plain)
        if progress:
            progress(total)
        index += 1
        if not is_full or last:
            break
    return total


# --------------------------------------------------------------------------
# Обёртки над файлами
# --------------------------------------------------------------------------

def _open_out(path) -> BinaryIO:
    """Открывает файл на запись, не затирая существующий молча."""
    return open(path, "xb") if not isinstance(path, int) else path


def encrypt_file(src_path, dst_path, *, overwrite: bool = False, **kw) -> int:
    if not overwrite and Path(dst_path).exists():
        raise FileExistsError(
            f"{dst_path} exists; pass overwrite=True to replace it")
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        return encrypt_stream(src, dst, **kw)


def decrypt_file(src_path, dst_path, *, overwrite: bool = False, **kw) -> int:
    if not overwrite and Path(dst_path).exists():
        raise FileExistsError(
            f"{dst_path} exists; pass overwrite=True to replace it")
    tmp = Path(str(dst_path) + ".part")
    try:
        with open(src_path, "rb") as src, open(tmp, "wb") as dst:
            n = decrypt_stream(src, dst, **kw)
    except BaseException:
        # Частично расшифрованный файл не должен оставаться под именем
        # результата: иначе аутентификация есть, а на диске лежит мусор,
        # который выглядит как успешный результат.
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(dst_path)
    return n


if __name__ == "__main__":
    import io
    import secrets

    key = secrets.token_bytes(32)
    for size in (0, 1, 1023, 1024, 4096, 300_000):
        data = secrets.token_bytes(size)
        buf = io.BytesIO()
        encrypt_stream(io.BytesIO(data), buf, key=key, chunk_size=MIN_CHUNK)
        out = io.BytesIO()
        decrypt_stream(io.BytesIO(buf.getvalue()), out, key=key)
        assert out.getvalue() == data, f"roundtrip failed at {size}"

    # Усечение обязано быть замечено.
    data = secrets.token_bytes(5000)
    buf = io.BytesIO()
    encrypt_stream(io.BytesIO(data), buf, key=key, chunk_size=MIN_CHUNK)
    blob = buf.getvalue()
    cut = blob[:HEADER_BYTES + (MIN_CHUNK + TAG_BYTES) * 2]
    try:
        decrypt_stream(io.BytesIO(cut), io.BytesIO(), key=key)
        raise SystemExit("FAIL: truncation was not detected")
    except AuthenticationError:
        pass

    print("dedalyan_file.py: self-check OK")
