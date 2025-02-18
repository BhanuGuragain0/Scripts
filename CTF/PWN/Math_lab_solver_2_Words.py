from pwn import *

r = remote("172.100.100.3", 4444)
r.recvline()
r.recvline()

for i in range(1, 21, 1):
    a = r.recvline()
    b = a.decode().replace("What is ", "").replace("?", "")
    d = eval(b)
    r.sendlineafter("Your answer:", str(d).encode())

print(r.recvline())
