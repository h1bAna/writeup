from pwn import *


def sort(arr1):
    print(arr1[-1])
    arr1 = arr1[-1].decode()
    print(arr1[-1])
    arr1 = arr1[1:-1]
    arr1 = list(arr1.split(' '))
    for i in range(0, len(arr1)):
        arr1[i] = int(arr1[i])
    arr1.sort()
    arr1 = str(arr1).replace(',', '')
    return arr1.encode()


s = remote('103.28.172.12', 1111)
arr = s.recvlines(8)
s.sendline(sort(arr))
try:
    while True:
        temp = s.recvlines(3)
        s.sendline(sort(temp))
except:
    print(s.recvlines(1))
