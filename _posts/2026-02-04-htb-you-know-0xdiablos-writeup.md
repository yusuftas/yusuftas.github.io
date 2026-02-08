---
title: "HTB: You Know 0xDiablos Challenge Writeup"
date: 2026-02-04
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

Last year I attended a CTF and tried to solve binary exploitation challenges, and I failed miserably. So I decided to challenge myself to learn how to PWN binaries: One PWN writeup a week. This is the first writeup of my challenge series, I decided to go a bit easy on myself and target an easy binary this week: https://app.hackthebox.com/challenges/You%2520know%25200xDiablos  You Know 0xDiablos challenge from hackthebox.  

## 1. Tools

- Pwndbg
- pwntools in Python
- Ghidra

## 2. First look
Before diving into static and dynamic analysis, I wanted to see what the binary does. Please don't try this on binaries that you think could be malicious :) So I just simply execute the binary and see what it does.

```
./vuln
You know who are 0xDiablos: 
testing testing
testing testing

./vuln
You know who are 0xDiablos: 
%p %p %p %p
%p %p %p %p

./vuln
You know who are 0xDiablos: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
```

I first tried providing a simple input and it echoed back what I provided. At this point I assumed it could have a **format string bug** and my test string didn't leak any memory. So this led me to test for a buffer overflow. As you can see from segmentation fault, it does indeed have a buffer overflow.

## 3. Static Analysis - Finding the bug
Static analysis involves looking at source code of the binary generally to find attack surfaces, bugs and anything we could exploit. Since we are not provided with a source code, it is time for decompiling! Decompiling involves disassembling the binary and trying to convert the assembly back to a more human readable C code. For decompiling, I have been using **Ghidra** for a while but any other tool could work as well, so feel free to use your favourite choice of disassembler/decompiler. 

![](/assets/img/diablos_main_func.png){: w="250" .left} ![](/assets/img/diablos_vulnn_func.png){: w="200" .left}

Looking at the decompiled code. I could see two interesting functions: vuln and flag. Here we are looking at main function. First part I marked can be ignored, it is a very common pattern used in pwn challenges to make standard output flash quicker. It then prints a text in second marked place with puts, and then calls the vuln function. So looking at this main, there is nothing important here that can be exploited. So we move to the vuln function.  

We found our bug! There is a 180 bytes buffer used to get input using gets function. gets function doesn't perform bounds checking and hence it is extremely vulnerable to overflow attacks. Cpp reference mentions that is is deprecated in C++11 and removed in C++14.

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> Never use gets, no bound checking!! fgets is a safer alternative.
{: .prompt-danger }
<!-- markdownlint-restore -->

We now know that there is a buffer overflow. The question is what do we do with it? We overflow it of course! This buffer is stored in stack. In C/C++ memory can be allocated in two different positions: **stack and heap**. If the memory is created through new, malloc and similar functions it is stored in heap, otherwise it is stored in stack. I will leave it to the reader to research further, otherwise this writeup will be much longer than I expected. In summary, **this buffer is stored in stack and since there is no bound checking in gets, we can overflow to stack and manipulate the memory in stack**

### Stack
> Stack is used to store variables, and most importantly EIP/RIP -> instruction pointer
{: .prompt-info } 

EIP/RIP is the instruction pointer register. In simple terms, EIP points to memory location which contains the instruction being executed. When the computer is executing instructions, there are certain places where the code jumps around, like when we call a function. Function is a group of instructions stored in a different place. When a function needs to be called that is in a different memory location, last instruction's memory that was pointed by EIP/RIP pushed to the stack. Then when the function is returning it can return back to that position using that value in the stack and code execution can continue from where it was left off (note this is done by **ret** instruction which pops the value stored in the stack to EIP/RIP).

> **Since the buffer is stored in stack, and we can overflow the buffer, that means there is a stack buffer overflow bug here. And stack stores the ret address**
{: .prompt-info } 
 

This means by overflowing the buffer and overriding the return address we can return to any place!! This place could be a library function, another function in binary, or just any arbitrary position in the code. That is quite a powerful tool to utilize but we have to know the address we want to return to. Looking at other functions in the ghidra, we can see there is a function called flag:

![Function we need to jump to](/assets/img/diablos_flag_func_dark.png)


Very interesting function. I have done a bit of clean up on the ghidra's decompile output, but nevertheless it is quite easy to understand. Function takes two parameters, if the right parameter values are given, it reads the flag file and prints the contents of the file. We found our target function to return to. Now to be able to return to this function and get it to print contents of the flag file:

1. Overwrite the return pointer to address of this function
2. Provide param1 = 0xdeadbeef
3. Provide param2 = 0xc0ded00d

### checksec

Now that we have a general idea of what we are targetting, let's have a look at checksec output which shows the security related flags the binary compiled with. Red means bad for safety, good for attacker. 

![Checksec results of the binary](/assets/img/diablos_checksec.png)

Looking at these results, it is pretty obvious that this is an easy target. Nearly all of security flags are disabled which makes our job way easier. For this challenge and buffer overflow we are going to execute we are mainly interested in two of the flags:

1. No canary: When we overflow the buffer, there is no safety check added by the compiler to detect that stack has been smashed.
2. No PIE: Code is not loaded with a random memory offset, meaning that the function addresses we see in ghidra or any decompiler will be exactly same.

With these two flags disabled, stack overflow logic becomes more simpler and easy to execute. So we can simply use the address we see here 0x080491e2 as the return address we will jump to:

![](/assets/img/diablos_flag_address.png)

## 4. Dynamic Analysis - Exploiting the bug

Next step is to actually exploit the bug. We know the buffer is vulnerable to overflow and we have to overflow such that we override the return address to the address we found above. But how do we actually find how much to overflow? By debugging and a bit trial and error :D For this purpose I will be using pwntools and pwndbg, they are really great tools, but I will try not to go into too much details on how to use these tools. Looking at the post, it is getting too long and it is not really scope of this blog post to go into that much details on tool usage. I will leave it to reader to explore further. 

First problem is: **finding the offset to return address in stack **. This offset tells us how big of an input we need to provide to reach to the stored return address in stack. More experience people use cyclic patterns to overflow the buffer to find exact values, but I am not like them. I am inexperienced, amateur and a bit lazy. I debug and look at the stack to figure it out. So I used this pwntools script to add a break point right after the gets function returns:

```python
# This script is generated using pwntools template and have been modified accordingly
from pwn import *

# Set up pwntools for the correct architecture
exe = './vuln'

context.binary = exe
elf = ELF(exe)

context.terminal = ['cmd.exe', '/c', 'start', 'wsl.exe', '-d', 'Ubuntu']

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
b *vuln+36
'''.format(**locals())

# Local process
io = start()
io.recvuntil(b'0xDiablos: ')        # Recv until this is printed

# Just some AAAAA as input to the gets, this shouldn't overflow the buffer
payload = b'A' * 100 

# Send it and debug 
io.sendline(payload)
io.interactive()
```

Most of the script is from the pwntools template generator. I modified to run under WSL and added the breakpoint line. To find where to stop and debug the binary, I looked the disassembled code and decided to stop right after gets function finishes in vuln() function. At that point, our input should be in the stack and visible. If pwndbg is setup properly, when GDB is launched it should update to pwndbg console which has many more tools than a pure GDB debugger. To run the script python3 solve.py GDB and then c/continue to start the execution in the debugger. Hopefully you will get the debugger stop at the *vuln + 36:

![](/assets/img/diablos_pwndbg_screen1.png)

Looking at this, stack does indeed have our input but since the buffer isn't really small, we can't really see return address we are looking for in the stack. By the way, the return address we are looking for in the stack can be found easily in the disassembler window by looking at the next instruction after the vuln function call:

![](/assets/img/diablos_return_address.png){: w="250" }

Next instruction after call vuln is shown as main + 103. pwndbg is a smart debugger, it also displays such addresses with its relative offsets, so we should be able to see that address in the stack if we look at a larger portion of stack by using stack 60 in pwndbg console:

![Finding the offset](/assets/img/diablos_finding_offset.png)

Okay we can see where the our buffer is and where the normal return address is:  0x10 and 0xcc offsets in the stack. Stack grows downwards interestingly, so any lower address has been pushed to stack later compared to higher addresses. Using these two offsets we can see the difference between them is **0xcc - 0x10 = 188 That means if we provide 188 bytes input, next 4 bytes we provide will override the return address**. To test this idea, let's make a small change to our payload, and provide the flag function's return address by packing it little endian style:

```
payload = b'A' * 188 + p32(0x080491e2)
```

And now we rerun the script and break at the same point to see if we could achieve our first goal:

![Return address overriden](/assets/img/diablos_return_overriden.png)

That looks like success!! If you let the run continue, you will see that it indeed goes inside the flag function. You can also check the call stack in pwndbg console to see the same thing. 

### Function Parameters - Final Boss

If you are following along, you can see that after we manage to call flag function it didn't print the flag file. The reason is, it is expecting two arguments and checking if their values are expected values. **Question is how do we provide these arguments? Answer depends on the architecture:**

1. x86: They are provided through stack.
2. x64: First four arguments through registers, and after that through stack.
3. Others: I don't know yet.

Conveniently challenge is x86 based, and we have a stack overflow vulnerability :D Since they are provided through stack, we just have to know where we need to put them to overflow the buffer and send the required values. I will be honest, at this part I just did trial and error to find where to send them. Since we can debug, all you have to do is send some data and see where it ends up when you are inside the flag function and then move the position of your data by how much it is offset by. Debugging makes this a fairly easy trial and error problem. I am sure experienced ctf players, professionals etc must be cringing on what I am suggesting but honestly go and try and have fun, you got a powerful debugger with you :)

Final result in the end is this for local testing:

```python
from pwn import *

exe = './vuln'
context.binary = exe

# Local process
io = start()
io.recvuntil(b'0xDiablos: ')        # Recv until this is printed

# Make sure to pack according to the arch. 
payload = b'A' * 188 + p32(0x080491e2) + b'A' * 4 + p32(0xdeadbeef) + p32(0xc0ded00d) 

io.sendline(payload)
io.interactive()
```

If you have a flag.txt file in the same directory, this overflow should provide the right parameters and flag function should print the contents of the flag.txt file. All in all it was a pretty easy challenge with essentially one line of payload, though I learned quite a lot from it. Documenting it took much longer than I thought and I ended up writing this like a tutorial rather than a writeup. Thank you for reading it to the end. And as always, keep learning!



