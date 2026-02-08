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

EIP/RIP is the instruction pointer register. In simple terms, EIP points to memory location which contains the instruction being executed. When the computer is executing instructions, there are certain places where the code jumps around, like when we call a function. Function is a group of instructions stored in a different place. When a function needs to be called that is in a different memory location, last instruction's memory that was pointed by EIP/RIP pushed to the stack. Then when the function is returning it can return back to that position using that value in the stack and code execution can continue from where it was left off (note this is done by **ret** instruction which pops the the value stored in the stack to EIP/RIP).   


![Checksec results of the binary](/assets/img/diablos_checksec.png)


![Function we need to jump to](/assets/img/diablos_flag_func.png)