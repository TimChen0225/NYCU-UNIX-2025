#!/usr/bin/env python3
# -*- coding: utf-8 -*-
## Lab sample file for the AUP course by Chun-Ying Huang

import sys
from pwn import *

# from solpow import solve_pow
import base64
import zlib
import time
from itertools import permutations


def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print(time.time(), "solving pow ...")
    solved = b""
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == "000000":
            solved = str(i).encode()
            print("solved =", solved)
            break
    print(time.time(), "done.")
    r.sendlineafter(b"string S: ", base64.b64encode(solved))
    z = r.recvline()
    print(z.decode().strip())
    z = r.recvline()
    print(z.decode().strip())


def decode_msg(msg):
    data = base64.b64decode(msg.encode())
    length = int.from_bytes(data[:4], "little")
    return zlib.decompress(data[4:]).decode()


def encode_msg(msg):
    compressed = zlib.compress(msg.encode())
    length = len(compressed).to_bytes(4, "little")
    # print(base64.b64encode(length + compressed))
    return base64.b64encode(length + compressed).decode()


def decode_AB(encoded_msg):
    data = base64.b64decode(encoded_msg.encode())

    length = int.from_bytes(data[:4], "little")

    decompressed = zlib.decompress(data[4:])

    a = int.from_bytes(decompressed[:4], "big")
    b = int.from_bytes(decompressed[5:9], "big")

    print(f"{a}A{b}B")
    return a, b


def pow_solver():
    if len(sys.argv) > 1:
        ## for remote access
        r = remote("up.zoolab.org", 10155)
        solve_pow(r)
    else:
        ## for local testing
        r = process("./guess.dist.py", shell=False)

    msg = r.recvline().strip().decode()
    response = decode_msg(msg)
    print(response)

    possible_numbers = ["".join(p) for p in permutations("0123456789", 4)]
    for count in range(10):
        # read input msg
        msg = r.recvline().strip().decode()
        response = decode_msg(msg)
        print(response)

        # input guess
        # === human ===
        # guess = input().strip()
        # r.sendline(encode_msg(guess))
        # === computer ===
        guess = possible_numbers[0]
        print(f"Computer Guess {guess}")
        r.sendline(encode_msg(guess))

        # get ab hint
        msg = r.recvline().strip().decode()
        a, b = decode_AB(msg)

        # update possible answer
        possible_numbers = [
            num
            for num in possible_numbers
            if sum(g == s for g, s in zip(num, guess)) == a
            and sum(
                (num.count(d) > 0) and (num[i] != guess[i]) for i, d in enumerate(guess)
            )
            == b
        ]

        # read status msg
        msg = r.recvline().strip().decode()
        response = decode_msg(msg)
        print(response)

        if a == 4:
            break

    # r.interactive()
    r.close()


if __name__ == "__main__":
    pow_solver()
