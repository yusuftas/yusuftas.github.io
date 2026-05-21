---
title: "NDIAS Auto/IoT CTF: Tiny Crackme Writeup"
date: 2026-05-18
categories: 
  - "reverse-engineering"
  - "re"
tags: 
  - "reveng"
  - "re"
  - "ctf"
  - "ndias_ctf"
  - "iot_ctf"
---

After the CTF ended I decided to see if I can solve the Reverse Engineering challenge. It was labelled, and I thought how hard could it be really. I was in for a surprise! This is my first writeup for a RE challenge, so I might be over simplifying or over complicating certain stuff. But since I am a beginner in RE, expect this writeup to be more catered towards beginners like me. 

## First Look

We are given a binary and a run script. Just by looking at the run script we can see that it is an ARM binary:

```
qemu-system-arm \
    -machine mps2-an385 \
    -cpu cortex-m3 \
    -kernel kernel \
    -monitor none \
    -nographic \
    -serial stdio \
    -semihosting \
    -semihosting-config enable=on,target=native
```

Well it is an architecture I haven't worked on before, this will be fun. Next, I loaded the binary to Ghidra and let it do its magic. There are hundreds of functions in the binary and they are stripped. But at least Ghidra managed to label the entry function:

![Entry](/assets/img/tiny_funcs.png)

Following the function calls `FUN_000120b4 -> FUN_00012122 -> FUN_0001336c` we end up in a function that looks like main:

![Main](/assets/img/tiny_main.png)

In this function, FUN_0000143e got my attention. It takes a pointer to a code address, and it is called twice with two different strings: 'uart' and 'ctf'. At this point, I decided to use Claude to help me understand decompiled functions. After checking a couple of them, we reached to a conclusion that these functions was coming from Free RTOS and FUN_0000143e was a task create function. Something similar to this:  <https://www.freertos.org/Documentation/02-Kernel/04-API-references/01-Task-creation/01-xTaskCreate>

So what this means is we have two separate tasks started in main, something like threads I would say. We can see the starting point of tasks in the function call: `&LAB_00013270+1`  and `0x132a5`. Ghidra is quite helpful that we can navigate to these points in code by simplying clicking them.

## CTF Task

Well given that task is named CTF, I decided to look into it first. Just by following function calls, we end up in this function:

![Flag CTF](/assets/img/tiny_flag_ctf.png)

We can easily see the expected flag format in the if checks: `FLAG{30chars}`. We can also see that the content of the flag - 30 characters is sent into a different function. Looking inside that function we can see three long strings of data: 

![SHA](/assets/img/tiny_sha.png)

I used Claude to understand what was happening in that function and labelled functions accordingly. We come to the conclusion that this function is creating some kind of hash of the given input string. Long bytes of data seen in the decompilation is parameters of a eliptic curve crypto, to be more specific this one: <https://std.neuromancer.sk/nist/B-283>

Returned hash of this function is compared against a hash in the code stored in globals: `61d28525a11e985f95083043e6b04d99a891936d7d35304fac08cfb6c079a647` . Well if we could reverse that hash, it would be awesome :) But that is no easy task, not even something feasible. And now that I think about it, having parameters of a proper ECC should be an indication that this crypto isn't weak. Looking around in the code, I can't see a way to go back to flag from this hash.

At this point, I was stuck. Since the ctf was over, I reached out to organizers and they provided very big hints for the solution. Thanks to them, I was able to solve it. Now let's continue.

## UART Task

Remember we had one more task running, uart task? Organizers pointed that I needed to dive deeper into the UART function. It actually didn't look very interesting at first glance:

![UART](/assets/img/tiny_uart.png)

Since the hint was pointing to that, I checked each function here and followed this trail of functions:

`00013270 -> FUN_00010418 -> FUN_00001128 -> FUN_00005b7c -> FUN_00005a50 -> FUN_000121a4`

That was a long line of functions! If I wasn't told that solution was here, I probably wouldn't be able to find this function. At the end of the pipe, we reach to a CRC32 calculation function:

![CRC32](/assets/img/tiny_crc32.png)

We can see the parameters of the CRC matches the description here: <https://wiki.osdev.org/CRC32> . I didn't want to risk implementing this myself, so I got Claude to write the crc function for me:

```python
TABLE = [0] * 256
for i in range(256):
    crc = i
    for _ in range(8):
        crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    TABLE[i] = crc

def crc32_byte(crc, byte):
    return (crc >> 8) ^ TABLE[(crc ^ byte) & 0xFF]

def crc32(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = crc32_byte(crc, b)
    return (~crc) & 0xFFFFFFFF
```

But why is this CRC important? Let's go back to one previous function where the crc32 gets called:

![CRC results](/assets/img/tiny_every5.png)

CRC function is called after every 5 character is received. And we can see the expected CRC results in the code there. What this means is we know expected CRC of : `crc32(flag[n:n+5])` where n = 0, 5, 10, 15, 20, 25

What this means is we need to do some brute forcing of the expected CRC values to find what 5 characters would generate such values using this CRC32. If we can reverse all of them, we will get the flag's 30 characters! I used a couple of tricks to make the search faster: using a pregenerated lookup table, going backwards from last byte and finding 4 byte candidates using the lookup table. Here is the solver:

```python
import itertools
import string
from multiprocessing import Pool

# ── CRC-32 forward ───────────────────────────────────────────────────────────
TABLE = [0] * 256
for i in range(256):
    crc = i
    for _ in range(8):
        crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    TABLE[i] = crc

def crc32_byte(crc, byte):
    return (crc >> 8) ^ TABLE[(crc ^ byte) & 0xFF]

def crc32(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = crc32_byte(crc, b)
    return (~crc) & 0xFFFFFFFF

# ── CRC-32 reverse ───────────────────────────────────────────────────────────
# Build reverse table: given output byte of CRC step, recover input CRC state
REVERSE_TABLE = [0] * 256
for i in range(256):
    REVERSE_TABLE[TABLE[i] >> 24] = i  # high byte of output maps back to input

def crc32_reverse_byte(crc_after, byte_in):
    """Given CRC state AFTER processing byte_in, recover CRC state BEFORE."""
    # crc_after = (crc_before >> 8) ^ TABLE[(crc_before ^ byte_in) & 0xFF]
    # High byte of crc_after came purely from TABLE[...] >> 24 ... reconstruct:
    top = (crc_after >> 24) & 0xFF
    idx = REVERSE_TABLE[top]              # recover the table index
    low_byte = idx ^ byte_in             # (crc_before ^ byte_in) & 0xFF = idx
    crc_before = ((crc_after ^ TABLE[idx]) << 8) | low_byte
    return crc_before & 0xFFFFFFFF

# ── Build 4-byte CRC state → 4-byte string lookup ───────────────────────────
def build_4byte_table(charset):
    """Map every possible CRC state after 4 charset bytes → those 4 bytes."""
    print("Building 4-byte forward table...")
    lookup = {}
    for combo in itertools.product(charset, repeat=4):
        crc = 0xFFFFFFFF
        for c in combo:
            crc = crc32_byte(crc, ord(c))
        lookup[crc] = combo  # crc_state_after_4_bytes → (c0,c1,c2,c3)
    print(f"Table built: {len(lookup):,} entries")
    return lookup

# ── Solver ───────────────────────────────────────────────────────────────────
def solve_chunk(args):
    idx, expected, lookup, charset = args

    # Final CRC after ~: undo the final XOR to get raw CRC state after 5 bytes
    crc_after_5 = (~expected) & 0xFFFFFFFF

    for last_byte in charset:
        # Reverse one CRC step: what was the CRC state after 4 bytes?
        crc_after_4 = crc32_reverse_byte(crc_after_5, ord(last_byte))

        # Look up whether any 4-char combo produces this state
        if crc_after_4 in lookup:
            first_four = ''.join(lookup[crc_after_4])
            return idx, first_four + last_byte

    return idx, None

# Expected CRC results taken from Ghidra
EXPECTED = [
    0x80B0CEE1,
    0x71F28109,
    0xF38B1F2F,
    0xFB2059C6,
    0x334BD5E1,
    0x8DD5DB45,
]

CHARSET = list(string.ascii_letters + string.digits + '_')

lookup = build_4byte_table(CHARSET)

args = [(i, exp, lookup, CHARSET) for i, exp in enumerate(EXPECTED)]


flag = 'FLAG{'
for a in args:
    idx, chunk = solve_chunk(a)
    if chunk:
        print(f"Chunk {idx+1}/6: '{chunk}'  CRC verify: 0x{crc32(chunk.encode()):08X}")
    else:
        print(f"Chunk {idx+1}/6: NOT FOUND — try expanding CHARSET")
        chunk = '?????'
    flag += chunk
flag += '}'

print(f"\n{flag}")
```

It should take a couple of seconds to run and get the flag:

```
Building 4-byte forward table...
Table built: 15,752,961 entries
Chunk 1/6: 'L0W_L'  CRC verify: 0x80B0CEE1
Chunk 2/6: '4Y3R_'  CRC verify: 0x71F28109
Chunk 3/6: 'SK1LL'  CRC verify: 0xF38B1F2F
Chunk 4/6: 'S_M4Y'  CRC verify: 0xFB2059C6
Chunk 5/6: '_H3LP'  CRC verify: 0x334BD5E1
Chunk 6/6: 'S_Y0U'  CRC verify: 0x8DD5DB45

FLAG{L0W_L4Y3R_SK1LLS_M4Y_H3LPS_Y0U}
```

## Final Notes
It was a really well designed challenge with a good red herring to catch players and LLMs off guard. I fell for the trick and assumed it was the ECC until I reread the challenge description. There was a good hint there that the heavy looking part may not be important. Thanks to the organizers, I managed to reach to the solution. I enjoyed this CTF a lot and learned quite a few things. Until next one, keep learning!