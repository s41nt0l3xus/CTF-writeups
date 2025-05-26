#!/usr/bin/env python3

from hashlib import sha256
import binascii
import struct
import sys


def solve_pow(challenge: bytes) -> str:
    idx = 0
    while True:
        sol = sha256(challenge + struct.pack("<Q", idx)).hexdigest()[0:6]
        if idx % 1000000 == 0:
            print(f"[+] Progress: {idx}. Current attempt: {sol}")
        if sol == "000000":
            return struct.pack("<Q", idx).hex()
        idx += 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <challenge>")
    else:
        print(solve_pow(sys.argv[1].encode()))
