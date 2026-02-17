#!/usr/bin/env python3
import argparse
import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
try:
    import zstandard as zstd
except ModuleNotFoundError as e:
    raise SystemExit(
        "Missing dependency 'zstandard'. Install it with: python3 -m pip install zstandard"
    ) from e


def aes_cbc_pkcs7_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def zstd_decompress_all(data: bytes) -> bytes:
    dctx = zstd.ZstdDecompressor()
    with dctx.stream_reader(data) as r:
        out = r.read()
    return out


def main():
    ap = argparse.ArgumentParser(description='Decrypt bunaken_dist_clean/flag.txt.bunakencrypted')
    ap.add_argument(
        '--in',
        dest='in_path',
        default=None,
        help='Path to flag.txt.bunakencrypted (default: auto-detect in repo)',
    )
    args = ap.parse_args()

    candidates: list[Path]
    if args.in_path:
        candidates = [Path(args.in_path)]
    else:
        candidates = [
            Path('bunaken_dist_clean/flag.txt.bunakencrypted'),
            Path('bunaken_dist/flag.txt.bunakencrypted'),
            Path('flag.txt.bunakencrypted'),
        ]

    enc_path = next((p for p in candidates if p.exists()), None)
    if enc_path is None:
        checked = "\n".join(f"- {p}" for p in candidates)
        raise SystemExit(
            "Encrypted flag file not found. Checked:\n"
            f"{checked}\n\n"
            "Fix: pass --in <path>, e.g. --in bunaken_dist_clean/flag.txt.bunakencrypted"
        )

    b64 = enc_path.read_bytes().strip()
    raw = base64.b64decode(b64)
    if len(raw) < 16 or (len(raw) - 16) % 16 != 0:
        raise SystemExit(f'Unexpected ciphertext length: {len(raw)}')

    iv, ct = raw[:16], raw[16:]

    key_full = hashlib.sha256(b'sulawesi').digest()
    key = key_full[:16]

    zstd_bytes = aes_cbc_pkcs7_decrypt(key, iv, ct)
    pt = zstd_decompress_all(zstd_bytes)

    # Likely ASCII flag.
    try:
        print(pt.decode('utf-8'), end='')
    except UnicodeDecodeError:
        print(pt)


if __name__ == '__main__':
    main()
