"""Командная строка Dedalyan-96/256 (раздел 10.3 спецификации).

ВНИМАНИЕ. Шифр учебный, его стойкость не проверялась независимыми
криптоаналитиками. Не используйте его для защиты реальных данных.

Режим шифрования файлов -- CTR со 96-битным счётчиком (инкремент по модулю
2^96). CTR самообратен, поэтому encrypt и decrypt делают одно и то же;
обе команды оставлены для читаемости скриптов.

ВАЖНО про повторное использование счётчика: CTR катастрофически ломается,
если одна и та же пара (ключ, счётчик) использована дважды -- XOR двух
шифротекстов даёт XOR открытых текстов. По умолчанию генерируется случайный
96-битный счётчик, и он записывается в первые 12 байт выходного файла.

Примеры::

    python cli.py encrypt --key-hex <64 hex> --in a.txt --out a.enc
    python cli.py decrypt --key-hex <64 hex> --in a.enc --out a.txt
    python cli.py keystream --key-hex <64 hex> --bytes 1048576 --out ks.bin
    python cli.py block --key-hex <64 hex> --plaintext 0123456789abcdef01234567
    python cli.py schedule --key-hex <64 hex>
    python cli.py trace --key-hex <64 hex> --plaintext <24 hex>
    python cli.py selftest
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dedalyan as D

BLOCK_BYTES = D.BLOCK_BYTES
KEY_BYTES = D.KEY_BYTES
# Размер чанка ОБЯЗАН быть кратен размеру блока: иначе на стыке чанков
# счётчик перескочит через недоиспользованный блок гаммы и поток разъедется.
CHUNK = (1 << 20) - ((1 << 20) % BLOCK_BYTES)   # 1048572 = 87381 * 12
assert CHUNK % BLOCK_BYTES == 0


# --------------------------------------------------------------------------

def parse_key(args) -> bytes:
    """Ключ из --key-hex или --key-file. Ключ никогда не берётся из argv
    по умолчанию: в многопользовательской системе аргументы видны в ps."""
    if args.key_hex:
        h = args.key_hex.strip().replace(" ", "").replace("_", "")
        if h.startswith("0x"):
            h = h[2:]
        try:
            k = bytes.fromhex(h)
        except ValueError:
            raise SystemExit("ERROR: --key-hex is not valid hex")
        if len(k) != KEY_BYTES:
            raise SystemExit(f"ERROR: key must be {KEY_BYTES} bytes "
                             f"({KEY_BYTES * 2} hex chars), got {len(k)}")
        return k
    if args.key_file:
        data = Path(args.key_file).read_bytes()
        if len(data) == KEY_BYTES:
            return data
        text = data.decode("ascii", "ignore").strip()
        try:
            k = bytes.fromhex(text)
        except ValueError:
            raise SystemExit("ERROR: key file is neither 32 raw bytes nor hex")
        if len(k) != KEY_BYTES:
            raise SystemExit(f"ERROR: key file must hold {KEY_BYTES} bytes")
        return k
    raise SystemExit("ERROR: provide --key-hex or --key-file")


def get_engine(force_python: bool = False):
    """(name, ctx_factory, ctr_fn). ctr_fn(ctx, counter12, data) -> bytes."""
    if not force_python:
        from dedalyan_c import backend
        if backend.available:
            return ("C", lambda k: backend.new_ctx(k),
                    lambda ctx, ctr, data: backend.ctr(ctx, ctr, data,
                                                       len(data), D.N))
    return ("Python", lambda k: D.Dedalyan(k),
            lambda ctx, ctr, data: ctx.ctr(data,
                                           int.from_bytes(ctr, "big")))


def inc_counter(ctr: bytes, blocks: int) -> bytes:
    """Счётчик + blocks по модулю 2^96."""
    v = (int.from_bytes(ctr, "big") + blocks) & ((1 << 96) - 1)
    return v.to_bytes(12, "big")


# --------------------------------------------------------------------------

def cmd_crypt(args) -> int:
    key = parse_key(args)
    name, mk, ctr_fn = get_engine(args.python)
    ctx = mk(key)

    src = sys.stdin.buffer if args.infile == "-" else open(args.infile, "rb")
    dst = sys.stdout.buffer if args.outfile == "-" else open(args.outfile, "wb")

    try:
        if args.mode == "encrypt":
            if args.counter:
                counter = bytes.fromhex(args.counter)
                if len(counter) != 12:
                    raise SystemExit("ERROR: --counter must be 24 hex chars")
            else:
                counter = os.urandom(12)
            if not args.no_header:
                dst.write(counter)
        else:
            if args.counter:
                counter = bytes.fromhex(args.counter)
            elif args.no_header:
                raise SystemExit("ERROR: --no-header on decrypt requires "
                                 "--counter")
            else:
                counter = src.read(12)
                if len(counter) != 12:
                    raise SystemExit("ERROR: input too short to hold a counter")

        total = 0
        while True:
            # Читаем кратно блоку, иначе гамма разъедется на стыке чанков.
            chunk = src.read(CHUNK)
            if not chunk:
                break
            dst.write(ctr_fn(ctx, counter, chunk))
            counter = inc_counter(counter, (len(chunk) + BLOCK_BYTES - 1)
                                  // BLOCK_BYTES)
            total += len(chunk)
    finally:
        if src is not sys.stdin.buffer:
            src.close()
        if dst is not sys.stdout.buffer:
            dst.close()

    if args.outfile != "-":
        print(f"{args.mode}ed {total} bytes with the {name} backend", file=sys.stderr)
    return 0


def cmd_keystream(args) -> int:
    key = parse_key(args)
    name, mk, ctr_fn = get_engine(args.python)
    ctx = mk(key)
    counter = bytes.fromhex(args.counter) if args.counter else bytes(12)
    if len(counter) != 12:
        raise SystemExit("ERROR: --counter must be 24 hex chars")

    dst = sys.stdout.buffer if args.outfile == "-" else open(args.outfile, "wb")
    try:
        left = args.bytes
        while left > 0:
            # CHUNK кратен блоку, поэтому усечение нужно только на хвосте.
            take = min(CHUNK, left)
            dst.write(ctr_fn(ctx, counter, bytes(take)))
            counter = inc_counter(counter, (take + BLOCK_BYTES - 1) // BLOCK_BYTES)
            left -= take
    finally:
        if dst is not sys.stdout.buffer:
            dst.close()
    if args.outfile != "-":
        print(f"wrote {args.bytes} bytes of keystream ({name} backend)",
              file=sys.stderr)
    return 0


def cmd_seal(args) -> int:
    """Аутентифицированное шифрование файла (GCM-96, кадрированный формат)."""
    import dedalyan_file as F

    if args.key_hex or args.key_file:
        kw = {"key": parse_key(args)}
    else:
        import getpass
        if args.password is not None:
            pw = args.password
        elif not sys.stdin.isatty():
            raise SystemExit("ERROR: no key given and stdin is not a terminal;"
                             " use --key-hex, --key-file or --password")
        else:
            pw = getpass.getpass("Password: ")
            if args.mode == "seal" and pw != getpass.getpass("Repeat: "):
                raise SystemExit("ERROR: passwords do not match")
        kw = {"password": pw}

    src, dst = Path(args.infile), Path(args.outfile)
    if not src.is_file():
        raise SystemExit(f"ERROR: {src} is not a file")

    try:
        if args.mode == "seal":
            kw["chunk_size"] = args.chunk
            n = F.encrypt_file(src, dst, overwrite=args.force, **kw)
            extra = dst.stat().st_size - n
            print(f"sealed {n} bytes -> {dst} (+{extra} bytes of header "
                  f"and tags)", file=sys.stderr)
        else:
            n = F.decrypt_file(src, dst, overwrite=args.force, **kw)
            print(f"opened {n} bytes -> {dst}", file=sys.stderr)
    except FileExistsError as exc:
        raise SystemExit(f"ERROR: {exc}")
    except F.FileFormatError as exc:
        raise SystemExit(f"ERROR: {exc}")
    except F.AuthenticationError as exc:
        # Отдельный код возврата: скрипт должен уметь отличить подделку
        # от отсутствия файла или неверных аргументов.
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 3
    return 0


def cmd_block(args) -> int:
    key = parse_key(args)
    rounds = args.rounds
    if args.plaintext:
        p = int(args.plaintext, 16)
        c = D.encrypt_block(p, D.key_from_bytes(key), rounds)
        print(f"{c:024x}")
    elif args.ciphertext:
        c = int(args.ciphertext, 16)
        p = D.decrypt_block(c, D.key_from_bytes(key), rounds)
        print(f"{p:024x}")
    else:
        raise SystemExit("ERROR: provide --plaintext or --ciphertext")
    return 0


def cmd_schedule(args) -> int:
    key = parse_key(args)
    ks = D.key_schedule(D.key_from_bytes(key))
    for i, k in enumerate(ks):
        print(f"k[{i:2d}] = 0x{k:012x}")
    return 0


def cmd_labyrinth(args) -> int:
    key = parse_key(args)
    kl = D.split_key(D.key_from_bytes(key))[0]
    T0, T1 = D.build_labyrinth(kl)
    print(f"K_L = 0x{kl:016x}")
    print("T0 = [" + ", ".join(f"{v:x}" for v in T0) + "]")
    print("T1 = [" + ", ".join(f"{v:x}" for v in T1) + "]")
    fp = sum(1 for t in (T0, T1) for j, v in enumerate(t) if v == j)
    print(f"fixed points: {fp} of 32")
    return 0


def cmd_trace(args) -> int:
    key = parse_key(args)
    p = int(args.plaintext, 16)
    ki = D.key_from_bytes(key)
    L, R = (p >> 48) & D.M, p & D.M
    print(f"in : L={L:012x}  R={R:012x}")
    for i, (f, l, rr) in enumerate(D.encrypt_block_trace(p, ki, args.rounds)):
        print(f"r{i:2d}: F={f:012x}  L={l:012x}  R={rr:012x}")
    return 0


def cmd_selftest(args) -> int:
    import subprocess
    root = Path(__file__).resolve().parent
    print("running tests/run_all.py --profile quick ...")
    return subprocess.call([sys.executable, str(root / "tests" / "run_all.py"),
                            "--profile", "quick"], cwd=str(root))


def cmd_genkey(args) -> int:
    print(os.urandom(KEY_BYTES).hex())
    return 0


# --------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="dedalyan", description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="WARNING: research cipher. Do not protect real data with it.")
    ap.add_argument("--python", action="store_true",
                    help="force the pure-Python backend")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_key_args(p):
        p.add_argument("--key-hex", help="256-bit key as 64 hex characters")
        p.add_argument("--key-file", help="file holding the key (raw or hex)")

    for mode in ("encrypt", "decrypt"):
        p = sub.add_parser(mode, help=f"{mode} a file in CTR mode")
        add_key_args(p)
        p.add_argument("--in", dest="infile", required=True,
                       help="input file, or - for stdin")
        p.add_argument("--out", dest="outfile", required=True,
                       help="output file, or - for stdout")
        p.add_argument("--counter",
                       help="96-bit counter as 24 hex chars "
                            "(default: random on encrypt, read from the "
                            "file header on decrypt)")
        p.add_argument("--no-header", action="store_true",
                       help="do not store/read the counter in the file")
        p.set_defaults(mode=mode, func=cmd_crypt)

    for mode, helptext in (
            ("seal", "encrypt a file WITH authentication (GCM-96, recommended)"),
            ("open", "decrypt and verify a sealed file")):
        p = sub.add_parser(mode, help=helptext)
        add_key_args(p)
        p.add_argument("--password",
                       help="password (Argon2id); prompts if no key is given")
        p.add_argument("--in", dest="infile", required=True)
        p.add_argument("--out", dest="outfile", required=True)
        p.add_argument("--force", action="store_true",
                       help="overwrite the output file if it exists")
        if mode == "seal":
            p.add_argument("--chunk", type=int, default=256 * 1024,
                           help="plaintext frame size in bytes")
        p.set_defaults(mode=mode, func=cmd_seal)

    p = sub.add_parser("keystream", help="write raw CTR keystream")
    add_key_args(p)
    p.add_argument("--bytes", type=int, required=True)
    p.add_argument("--out", dest="outfile", default="-")
    p.add_argument("--counter")
    p.set_defaults(func=cmd_keystream)

    p = sub.add_parser("block", help="encrypt or decrypt one 96-bit block")
    add_key_args(p)
    p.add_argument("--plaintext", help="24 hex chars")
    p.add_argument("--ciphertext", help="24 hex chars")
    p.add_argument("--rounds", type=int, default=D.N,
                   help="round-reduced variant Dedalyan-96/256-rN")
    p.set_defaults(func=cmd_block)

    p = sub.add_parser("schedule", help="print the 16 subkeys")
    add_key_args(p)
    p.set_defaults(func=cmd_schedule)

    p = sub.add_parser("labyrinth", help="print the labyrinth tables")
    add_key_args(p)
    p.set_defaults(func=cmd_labyrinth)

    p = sub.add_parser("trace", help="per-round trace of one block")
    add_key_args(p)
    p.add_argument("--plaintext", required=True, help="24 hex chars")
    p.add_argument("--rounds", type=int, default=D.N)
    p.set_defaults(func=cmd_trace)

    p = sub.add_parser("genkey", help="print a fresh random key")
    p.set_defaults(func=cmd_genkey)

    p = sub.add_parser("selftest", help="run the quick test suite")
    p.set_defaults(func=cmd_selftest)

    args = ap.parse_args(argv)
    if not hasattr(args, "python"):
        args.python = False
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
