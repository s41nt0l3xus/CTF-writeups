#!/usr/bin/env python3

from sys import argv
from pwn import *

leak = argv[1]

leak_bytes = b''.join(p64(int(x, 16)) for x in leak.split('+'))
sig1       = leak_bytes[0x00*0:0x00*0+0x40]
sig2       = leak_bytes[0x50*1:0x50*1+0x40]
cipher     = leak_bytes[0x50*2:0x50*2+0x40] if not args.LOCAL else leak_bytes[0x50*2:0x50*2+0x20]

converter = process('./convert', level='critical')
converter.send(sig1)
sig1 = converter.recv(64)
converter.send(sig2)
sig2 = converter.recv(64)
converter.close()

# (c) GPT-o3

from hashlib import sha256
from Crypto.Cipher import AES

n     = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SHIFT = 1 << 128

msg1  = "Lord, grant me the strength to accept the things I cannot change; Courage to change the things I can; And wisdom to know the difference."
msg2  = "Wherever There Is Light, There Are Always Shadows"
assert(len(msg1) == 136)
assert(len(msg2) == 49)

z1_bytes = sha256(msg1.encode()).digest()
z2_bytes = sha256(msg2.encode()).digest()
z1, z2   = int.from_bytes(z1_bytes, "big"), int.from_bytes(z2_bytes, "big")
m1, m2   = int.from_bytes(z1_bytes[:16], "big"), int.from_bytes(z2_bytes[:16], "big")

# ── helper lambdas ─────────────────────────────────────────────────────────
b2i   = lambda b: int.from_bytes(b, "big")
inv   = lambda x: pow(x, -1, n)

# ── parse the two signatures we just received from the file ───────────────
r1, s1 = b2i(sig1[:32]), b2i(sig1[32:])
r2, s2 = b2i(sig2[:32]), b2i(sig2[32:])

R1, R2 = inv(r1), inv(r2)                       # r⁻¹  (mod n)

# ── collect all plausible private-key candidates ──────────────────────────
candidates = []

for s1_eff in (s1, (n - s1) % n):              # cope with canonical “low-s”
    P1 = (s1_eff * SHIFT % n) * R1 % n
    Q1 = ((s1_eff * m1 - z1) % n) * R1 % n

    for s2_eff in (s2, (n - s2) % n):
        P2 = (s2_eff * SHIFT % n) * R2 % n
        Q2 = ((s2_eff * m2 - z2) % n) * R2 % n

        A  = (P1 - P2) % n
        if A == 0:                                   # (extremely unlikely)
            continue

        X  = ( (Q2 - Q1) % n ) * inv(A) % n          # one modular solution

        # the *real* upper-half of the nonce must be < 2¹²⁸
        X  = X if X < SHIFT else X - n               # bring it into range
        if X >= SHIFT:                               # still too large → impossible
            continue

        # full nonces
        k1 = (X << 128) + m1
        k2 = (X << 128) + m2

        # derived private key
        d  = ( (s1_eff * k1 - z1) % n ) * R1 % n

        # cross-check with the 2nd signature
        if (s2_eff * k2 - z2) % n == (r2 * d) % n:
            candidates.append(d)

for d in candidates:
  key  = sha256(d.to_bytes(32, "big")).digest()[:16]
  iv   = d.to_bytes(32, "big")[:16]
  pt   = AES.new(key, AES.MODE_CBC, iv).decrypt(cipher)
  pad  = pt[-1]
  flag = pt[:-pad]
  print(flag)
