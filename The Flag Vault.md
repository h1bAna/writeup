# The Flag Vault 

![image 1](flagVault.jpg)

The Flow of program that if we input right pass we will get the Flag. We can see flag but we don't know the order of
characters. Move *6164616361726261h* = abracada( becuase little endian) to RAX and *6861686168617262h* = brahahah to
RDX. After that move RAX to *[rbp+s1]* RDX to *[rbp+var_18]* and move 61h ('a') to *[rbp+var_10]* (after var_10). So
we have "brahahaha". Well i guess this i a string "abracadabrahahaha" becuase s1 = -20h, var_18 = -18h, var_10 = -10.
The input store in s2. And we compare s1 s2. So run the program, input "abracadabrahahaha" and you get the flag.

## another way 
![another way](anotherway.png)
we can see the order of flag when it push it on stack to print.


*KCTF{welc0me_t0_reverse_3ngineering}*

