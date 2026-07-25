"""Демонстрация: пароль -> Argon2id -> ключи -> шифрование с аутентификацией.

Показывает всю цепочку целиком: пароль, параметры и соль Argon2, выведенные
ключи, nonce, шифротекст, тег аутентичности и результат расшифровки.

Зачем здесь Argon2id, а не «просто хеш». Пароль -- это не ключ: у него мало
энтропии, и SHA-256 от него перебирается на GPU со скоростью порядка 10^10
попыток в секунду. Argon2id -- победитель Password Hashing Competition, он
намеренно требует много памяти, из-за чего перебор на GPU и ASIC теряет
преимущество перед обычным процессором. Именно это, а не «криптостойкость
хеша», защищает слабый пароль.

Зачем здесь MAC. Режим CTR сам по себе не защищает целостность: шифротекст
есть открытый текст, сложенный с гаммой по XOR, поэтому переворот бита в
шифротексте переворачивает ровно тот же бит открытого текста, и расшифровка
об этом не сообщит. Атакующий, знающий или угадавший открытый текст, может
подменить его целиком, не зная ключа. Схема encrypt-then-MAC закрывает это:
тег считается от шифротекста и заголовка, проверяется ДО расшифровки, и
любое изменение конверта отвергается.

Разделение ключей. Argon2 выдаёт 64 байта, которые режутся надвое: первые
32 -- ключ шифра, вторые 32 -- ключ MAC. Один и тот же ключ нельзя
использовать для двух разных примитивов: взаимодействие между ними не
анализировалось, и в общем случае небезопасно.

Формат конверта версии 2::

    version    1 байт   = 0x02
    t_cost     1 байт   параметры Argon2, чтобы старые конверты
    lanes      1 байт     оставались читаемыми при смене настроек
    mem_kib    4 байта  big-endian
    salt      16 байт
    nonce      8 байт
    ciphertext N байт
    tag       16 байт   HMAC-SHA256, усечённый

Заголовок 31 байт, тег 16 -- накладные расходы 47 байт на сообщение.
Секретен только пароль; всё остальное хранится открыто.

Счётчик CTR собирается как nonce (8 байт) || счётчик блоков (4 байта),
поэтому уникальность гаммы гарантирована уникальностью nonce, а не
вероятностными соображениями. Отсюда предел на длину сообщения:
2^32 блоков по 12 байт = 48 ГиБ.

ВНИМАНИЕ: сам шифр Dedalyan учебный, его стойкость не проверялась
независимыми криптоаналитиками. Argon2 и HMAC здесь настоящие, шифр -- нет.
Для реальных данных берите AES-GCM или ChaCha20-Poly1305.

Запуск::

    python demo.py                      # спросит пароль
    python demo.py --demo               # готовый пароль, без ввода
    python demo.py --password "пароль" --text "сообщение"
    python demo.py --text-file secret.txt --password-file pw.txt
    python demo.py --decrypt <base64-конверт>
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import os
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Вывод меток -- английский (кириллица ломается в консоли Windows), но сам
# текст пользователя может быть любым, поэтому просим UTF-8 где возможно.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):        # старый Python или перенаправление
    pass

import dedalyan as D

try:
    from argon2.low_level import Type, hash_secret_raw
except ImportError:
    print("ERROR: argon2-cffi is not installed.\n"
          "       pip install argon2-cffi", file=sys.stderr)
    raise SystemExit(1)

# ---- формат конверта -----------------------------------------------------

VERSION = 2
SALT_BYTES = 16
NONCE_BYTES = 8
BLOCK_COUNTER_BYTES = D.BLOCK_BYTES - NONCE_BYTES      # 4
TAG_BYTES = 16
KEY_BYTES = D.KEY_BYTES                                # 32
MAC_KEY_BYTES = 32
HEADER_BYTES = 1 + 1 + 1 + 4 + SALT_BYTES + NONCE_BYTES   # 31

MAX_MESSAGE_BYTES = (1 << (8 * BLOCK_COUNTER_BYTES)) * D.BLOCK_BYTES   # 48 GiB

# Параметры Argon2id: второй рекомендованный набор из RFC 9106
# (64 МиБ памяти, 3 прохода, 4 потока). Первый рекомендованный -- 2 ГиБ
# и 1 проход -- тяжеловат для интерактивного ввода.
# На практике параметры калибруют под целевое время (250-500 мс), а не
# фиксируют навсегда: на медленной машине эти же значения дадут ~400 мс.
ARGON2_TIME = 3
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_LANES = 4

DEFAULT_PASSWORD = "correct horse battery staple"
DEFAULT_TEXT = ("Dedalyan-96/256 demo. Шифр учебный, Argon2 настоящий. "
                "The quick brown fox jumps over the lazy dog. 0123456789")


class AuthenticationError(Exception):
    """Тег не сошёлся: неверный пароль либо подделанный конверт."""


# ---- вывод ключей --------------------------------------------------------

def derive_keys(password: str, salt: bytes,
                t: int, m: int, p: int) -> tuple[bytes, bytes]:
    """Argon2id: пароль + соль -> (ключ шифра, ключ MAC).

    Один вызов на 64 байта, а не два вызова по 32: Argon2 дорогой, и
    платить за него дважды незачем. Разделение делается нарезкой вывода.
    """
    okm = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=KEY_BYTES + MAC_KEY_BYTES,
        type=Type.ID,
    )
    return okm[:KEY_BYTES], okm[KEY_BYTES:]


# ---- бэкенд шифра --------------------------------------------------------

def get_engine():
    """Возвращает (имя, ctr_fn), где ctr_fn(key_bytes, start_int, data) -> bytes.

    Интерфейс намеренно одинаковый для обоих бэкендов: раньше Python
    принимал счётчик как int, а C -- как bytes, и расхождение между
    реализациями могло пройти незамеченным.
    """
    try:
        from dedalyan_c import backend
        if backend.available:
            def _ctr(key: bytes, start: int, data: bytes) -> bytes:
                ctr_bytes = start.to_bytes(D.BLOCK_BYTES, "big")
                return backend.ctr(backend.new_ctx(key), ctr_bytes,
                                   data, len(data), D.N)
            return "C", _ctr
    except Exception:
        pass

    def _ctr(key: bytes, start: int, data: bytes) -> bytes:
        return D.Dedalyan(key).ctr(data, start)
    return "Python", _ctr


def cross_check_backends() -> str:
    """Сверяет C и Python на случайных данных, если доступны оба."""
    try:
        from dedalyan_c import backend
        if not backend.available:
            return "only Python available"
    except Exception:
        return "only Python available"

    key = secrets.token_bytes(KEY_BYTES)
    start = secrets.randbits(96)
    data = secrets.token_bytes(1000)

    def c_ctr(k, s, d):
        return backend.ctr(backend.new_ctx(k), s.to_bytes(D.BLOCK_BYTES, "big"),
                           d, len(d), D.N)

    ok = c_ctr(key, start, data) == D.Dedalyan(key).ctr(data, start)
    return "C == Python on 1000 random bytes" if ok else "MISMATCH -- do not trust output"


# ---- шифрование и расшифровка -------------------------------------------

def _ctr_start(nonce: bytes) -> int:
    """nonce (8 байт) || счётчик блоков (4 байта, начинается с нуля)."""
    return int.from_bytes(nonce + b"\x00" * BLOCK_COUNTER_BYTES, "big")


def _pack_header(t: int, m: int, p: int, salt: bytes, nonce: bytes) -> bytes:
    return (bytes([VERSION, t, p]) + m.to_bytes(4, "big") + salt + nonce)


def _unpack_header(header: bytes):
    if header[0] != VERSION:
        raise SystemExit(f"ERROR: unsupported envelope version {header[0]}")
    t, p = header[1], header[2]
    m = int.from_bytes(header[3:7], "big")
    salt = header[7:7 + SALT_BYTES]
    nonce = header[7 + SALT_BYTES:HEADER_BYTES]
    return t, m, p, salt, nonce


def encrypt(password: str, plaintext: bytes, t: int, m: int, p: int):
    """-> (envelope, salt, nonce, enc_key, mac_key, ciphertext, tag)"""
    if len(plaintext) > MAX_MESSAGE_BYTES:
        raise SystemExit(
            f"ERROR: message exceeds {MAX_MESSAGE_BYTES} bytes; the 32-bit "
            f"block counter would overflow into the nonce and repeat keystream")

    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    enc_key, mac_key = derive_keys(password, salt, t, m, p)

    header = _pack_header(t, m, p, salt, nonce)
    _, ctr = get_engine()
    ciphertext = ctr(enc_key, _ctr_start(nonce), plaintext)

    # Encrypt-then-MAC: тег покрывает заголовок И шифротекст. Если бы он
    # покрывал только шифротекст, атакующий подменил бы соль или nonce.
    tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()[:TAG_BYTES]

    return header + ciphertext + tag, salt, nonce, enc_key, mac_key, ciphertext, tag


def decrypt(password: str, envelope: bytes):
    """-> (plaintext, salt, nonce, enc_key, mac_key, ciphertext, tag)

    Бросает AuthenticationError, если тег не сошёлся. Расшифровка при этом
    не выполняется вообще: неаутентифицированные данные не обрабатываются.
    """
    if len(envelope) < HEADER_BYTES + TAG_BYTES:
        raise SystemExit("ERROR: envelope is too short to hold header + tag")

    header = envelope[:HEADER_BYTES]
    ciphertext = envelope[HEADER_BYTES:-TAG_BYTES]
    tag = envelope[-TAG_BYTES:]

    t, m, p, salt, nonce = _unpack_header(header)
    enc_key, mac_key = derive_keys(password, salt, t, m, p)

    expected = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()[:TAG_BYTES]
    # compare_digest, а не ==: обычное сравнение выходит на первом
    # несовпавшем байте, и время ответа выдаёт, сколько байт тега угадано.
    if not hmac.compare_digest(tag, expected):
        raise AuthenticationError(
            "authentication failed: wrong password or the envelope was modified")

    _, ctr = get_engine()
    plaintext = ctr(enc_key, _ctr_start(nonce), ciphertext)
    return plaintext, salt, nonce, enc_key, mac_key, ciphertext, tag


# ---- вспомогательный вывод ----------------------------------------------

def hexdump(data: bytes, width: int = 32, limit: int = 256) -> str:
    shown = data[:limit]
    lines = []
    for off in range(0, len(shown), width):
        lines.append("    " + shown[off:off + width].hex())
    if len(data) > limit:
        lines.append(f"    ... ({len(data) - limit} more bytes)")
    return "\n".join(lines)


def rule(title: str = "") -> None:
    if title:
        print(f"\n--- {title} " + "-" * max(2, 60 - len(title)))
    else:
        print("=" * 66)


def show_text(label: str, data: bytes) -> None:
    """Печатает текст и его hex: если терминал испортит вывод, hex останется."""
    try:
        s = data.decode("utf-8")
        printable = s if len(s) <= 300 else s[:300] + " ..."
        print(f"  {label}: {printable}")
    except UnicodeDecodeError:
        print(f"  {label}: <binary, {len(data)} bytes>")
    print(f"  {label} (hex):")
    print(hexdump(data))


def print_b64(data: bytes, limit: int = 512) -> None:
    b64 = base64.b64encode(data).decode()
    for off in range(0, min(len(b64), limit), 76):
        print("    " + b64[off:off + 76])
    if len(b64) > limit:
        print(f"    ... ({len(b64) - limit} more base64 chars)")


def read_password(args) -> str:
    if args.password_file:
        return Path(args.password_file).read_text(encoding="utf-8").strip()
    if args.password is not None:
        return args.password
    if args.demo:
        return DEFAULT_PASSWORD
    if not sys.stdin.isatty():
        print("  (stdin is not a terminal -- falling back to the demo password)")
        return DEFAULT_PASSWORD
    return getpass.getpass("Password: ")


# ---- главная функция -----------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="WARNING: research cipher. Argon2 and HMAC are real, Dedalyan "
               "is not vetted. Do not protect real data with this.")
    ap.add_argument("--password",
                    help="password on the command line -- convenient but it "
                         "lands in shell history and in the process list; "
                         "prefer the interactive prompt or --password-file")
    ap.add_argument("--password-file", help="read the password from a file")
    ap.add_argument("--demo", action="store_true",
                    help="use the built-in demo password, do not prompt")
    ap.add_argument("--text", help="text to encrypt")
    ap.add_argument("--text-file", help="read the plaintext from a file")
    ap.add_argument("--decrypt", metavar="B64",
                    help="decrypt a base64 envelope instead of encrypting")
    ap.add_argument("--time-cost", type=int, default=ARGON2_TIME)
    ap.add_argument("--memory-kib", type=int, default=ARGON2_MEMORY_KIB)
    ap.add_argument("--lanes", type=int, default=ARGON2_LANES)
    ap.add_argument("--serve", action="store_true",
                    help="run the local web UI instead of printing to console")
    ap.add_argument("--port", type=int, default=8765,
                    help="port for --serve (bound to 127.0.0.1 only)")
    ap.add_argument("--no-browser", action="store_true",
                    help="with --serve, do not open a browser automatically")
    args = ap.parse_args()

    # Веб-интерфейс спрашивает пароль в форме, поэтому до read_password дело
    # не доходит: ни один пароль не попадает ни в argv, ни в историю оболочки.
    if args.serve:
        import webui
        return webui.serve(args.port, not args.no_browser)

    t, m, p = args.time_cost, args.memory_kib, args.lanes
    if not (1 <= t <= 255 and 1 <= p <= 255):
        raise SystemExit("ERROR: --time-cost and --lanes must fit in one byte")
    if not (8 <= m < (1 << 32)):
        raise SystemExit("ERROR: --memory-kib out of range")

    engine, _ = get_engine()

    rule()
    print("Dedalyan-96/256 + Argon2id + HMAC -- password to ciphertext demo")
    rule()
    print(f"  cipher backend : {engine}")
    print(f"  backend check  : {cross_check_backends()}")
    print(f"  KDF            : Argon2id  (t={t}, m={m} KiB, p={p}, "
          f"out={KEY_BYTES + MAC_KEY_BYTES} B)")
    print(f"  cipher mode    : CTR, {NONCE_BYTES * 8}-bit nonce + "
          f"{BLOCK_COUNTER_BYTES * 8}-bit block counter")
    print(f"  authentication : encrypt-then-MAC, HMAC-SHA256 truncated to "
          f"{TAG_BYTES} bytes")

    password = read_password(args)

    # ---------------- расшифровка готового конверта ----------------------
    if args.decrypt:
        try:
            envelope = base64.b64decode(args.decrypt, validate=True)
        except Exception:
            raise SystemExit("ERROR: --decrypt expects valid base64")
        rule("Decrypting the supplied envelope")
        try:
            plaintext, salt, nonce, enc_key, _, _, tag = decrypt(password, envelope)
        except AuthenticationError as exc:
            print(f"  REJECTED: {exc}")
            print()
            print("  The tag is checked before decryption, so nothing was")
            print("  decrypted at all. This is the difference from plain CTR:")
            print("  a modified envelope or a wrong password is an error,")
            print("  not silently different plaintext.")
            return 1
        print(f"  salt           : {salt.hex()}")
        print(f"  nonce          : {nonce.hex()}")
        print(f"  tag            : {tag.hex()}  VERIFIED")
        print(f"  DECRYPTION KEY : {enc_key.hex()}")
        print()
        show_text("plaintext", plaintext)
        return 0

    # ---------------- шифрование ------------------------------------------
    if args.text_file:
        plaintext = Path(args.text_file).read_bytes()
    elif args.text is not None:
        plaintext = args.text.encode("utf-8")
    else:
        plaintext = DEFAULT_TEXT.encode("utf-8")

    rule("1. Input")
    print(f"  plaintext size : {len(plaintext)} bytes")
    show_text("plaintext", plaintext)

    rule("2. Key derivation (Argon2id)")
    t0 = time.perf_counter()
    envelope, salt, nonce, enc_key, mac_key, ciphertext, tag = \
        encrypt(password, plaintext, t, m, p)
    dt = time.perf_counter() - t0
    print(f"  salt (random, stored in the clear) : {salt.hex()}")
    print(f"  Argon2id time                      : {dt * 1000:.0f} ms")
    print()
    print("  Argon2 output is 64 bytes, split into two independent keys:")
    print(f"    CIPHER KEY : {enc_key.hex()}")
    print(f"    MAC KEY    : {mac_key.hex()}")
    print()
    print("  Both are reproducible from (password, salt) alone -- so the salt")
    print("  must be kept, and the password must be strong. Argon2's memory")
    print("  cost is what makes a weak password survive a GPU attack.")

    rule("3. Subkeys derived by Dedalyan from the cipher key")
    ks = D.key_schedule(D.key_from_bytes(enc_key))
    for i in range(0, 16, 4):
        print("    " + "  ".join(f"k[{j:2d}]={ks[j]:012x}"
                                 for j in range(i, i + 4)))

    rule("4. Encryption (CTR)")
    print(f"  nonce (random, stored in the clear): {nonce.hex()}")
    print(f"  CTR start value: {_ctr_start(nonce):024x}"
          f"   ({NONCE_BYTES * 8} bits nonce || counter = 0)")
    print()
    print("  ciphertext (hex):")
    print(hexdump(ciphertext))

    rule("5. Authentication (encrypt-then-MAC)")
    print(f"  tag = HMAC-SHA256(mac_key, header || ciphertext)[:16]")
    print(f"      = {tag.hex()}")
    print()
    print("  The tag covers the header too, so salt, nonce and the Argon2")
    print("  parameters cannot be swapped by an attacker either.")
    print()
    print("  envelope = header || ciphertext || tag, base64:")
    print_b64(envelope)
    print(f"  ({HEADER_BYTES} + {len(ciphertext)} + {TAG_BYTES} = "
          f"{len(envelope)} bytes total)")

    rule("6. Decryption")
    back, _, _, key2, _, _, _ = decrypt(password, envelope)
    print(f"  tag verified                        : yes")
    print(f"  key re-derived from password + salt : "
          f"{'identical' if key2 == enc_key else 'MISMATCH'}")
    show_text("decrypted", back)
    print()
    ok = back == plaintext
    print(f"  ROUNDTRIP: {'OK -- decrypted == original' if ok else 'FAILED'}")

    rule("7. Wrong password")
    try:
        decrypt(password + "!", envelope)
        print("  ERROR: a wrong password was accepted -- this is a bug")
        ok = False
    except AuthenticationError as exc:
        print(f"  REJECTED: {exc}")
        print()
        print("  Without a MAC, a wrong password produced garbage and no error.")
        print("  Now it is detected. Note the flip side: this also lets an")
        print("  attacker holding the envelope test password guesses offline.")
        print("  That was already true (guessed plaintext looks sensible), and")
        print("  Argon2's cost is what keeps such guessing expensive.")

    rule("8. Tampering")
    forged = bytearray(envelope)
    forged[HEADER_BYTES] ^= 0x01           # один бит шифротекста
    try:
        decrypt(password, bytes(forged))
        print("  ERROR: a modified envelope was accepted -- this is a bug")
        ok = False
    except AuthenticationError as exc:
        print(f"  flipped one bit of the ciphertext")
        print(f"  REJECTED: {exc}")
        print()
        print("  In plain CTR that bit flip would have flipped exactly the")
        print("  same bit of the plaintext, silently. An attacker who knows")
        print("  the plaintext could have replaced it entirely by computing")
        print("  keystream = ciphertext XOR plaintext -- no key required.")
        print("  The tag makes that a detected error instead.")

    rule("Reproduce this")
    print("  python demo.py --decrypt <base64 envelope>")

    rule()
    print("  Argon2id and HMAC-SHA256 are production-grade. Dedalyan is NOT --")
    print("  it is a research cipher with no independent cryptanalysis. For")
    print("  real data use AES-GCM or ChaCha20-Poly1305.")
    print()
    print("  Also note: Python cannot reliably wipe key material from memory")
    print("  (bytes are immutable and the GC copies them). The C backend can,")
    print("  and should, use explicit_bzero on its key context.")
    rule()

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
