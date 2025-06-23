#!/usr/bin/env python3

from pwn import *

context.arch = 'amd64'
context.os   = 'linux'

sc  = ''
sc += shellcraft.sh()
sc  = asm(sc);

print('[' + ','.join(hex(b) for b in sc) + ']')
