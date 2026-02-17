#!/usr/bin/env python3
"""Recover TLS RSA private key from a weak RSA-1024 certificate via Fermat factoring.

Input:  cert.der (X.509 DER) in repo root by default.
Output: server_rsa.pem (PKCS#1 PEM) in repo root by default.

This is intentionally offline/safe: it never touches the network.
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def is_perfect_square(n: int) -> tuple[bool, int]:
    if n < 0:
        return False, 0
    r = math.isqrt(n)
    return r * r == n, r


def fermat_factor(n: int, max_steps: int = 50_000_000) -> tuple[int, int]:
    """Fermat factorization for n = p*q with close primes."""
    if n % 2 == 0:
        return 2, n // 2

    a = math.isqrt(n)
    if a * a < n:
        a += 1

    for _ in range(max_steps):
        b2 = a * a - n
        ok, b = is_perfect_square(b2)
        if ok:
            p = a - b
            q = a + b
            if p * q == n and p != 1 and q != 1:
                return (p, q) if p < q else (q, p)
        a += 1

    raise RuntimeError("Fermat factoring failed: primes are not close enough or max_steps too small")


def load_rsa_pub_from_cert_der(cert_path: Path) -> rsa.RSAPublicKey:
    cert = x509.load_der_x509_certificate(cert_path.read_bytes())
    pub = cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError("Certificate public key is not RSA")
    return pub


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert-der", default="cert.der", help="Path to X.509 certificate (DER)")
    ap.add_argument("--out", default="server_rsa.pem", help="Output PEM path")
    ap.add_argument("--max-steps", type=int, default=5_000_000, help="Max Fermat iterations")
    args = ap.parse_args()

    cert_path = Path(args.cert_der)
    out_path = Path(args.out)

    pub = load_rsa_pub_from_cert_der(cert_path)
    numbers = pub.public_numbers()

    n = numbers.n
    e = numbers.e

    print(f"[*] RSA modulus bits: {n.bit_length()}")
    print(f"[*] e: {e}")

    print("[*] Fermat factoring... (this only works if p and q are very close)")
    p, q = fermat_factor(n, max_steps=args.max_steps)
    print("[+] Factored!")

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    priv_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    )

    priv = priv_numbers.private_key()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption(),
    )

    out_path.write_bytes(pem)
    print(f"[+] Wrote: {out_path}")


if __name__ == "__main__":
    main()
