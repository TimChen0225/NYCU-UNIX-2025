from pwn import *

host = "ipinfo.io"
port = 80

conn = remote(host, port)

http_request = (
       b"GET /ip HTTP/1.1\r\n"
       b"Host: ipinfo.io\r\n"
       b"User-Agent: curl/8.7.1\r\n"
       b"Accept: */*\r\n"
       b"Connection: close\r\n"
       b"\r\n"
       )

conn.send(http_request)

response = conn.recvall().decode()

ip = response.split("\r\n")[-1]

print(ip)

