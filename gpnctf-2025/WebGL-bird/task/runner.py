#!/usr/bin/env python3

from pwn import *
from sys import argv
from base64 import b64encode

file     = open(argv[3], 'rb').read()
file_b64 = b64encode(file)

io = remote(argv[1], int(argv[2])) if args.LOCAL else remote(argv[1], int(argv[2]), ssl=True)
io.sendlineafter(b'empty line:\n', file_b64)
io.sendline(b'')
io.interactive()
