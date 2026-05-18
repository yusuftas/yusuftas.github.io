---
title: "NDIAS Auto/IoT CTF: Keyfob Challenges Writeup"
date: 2026-05-18
categories: 
  - "signals"
  - "keyfob"
tags: 
  - "signals"
  - "rf"
  - "ctf"
  - "ndias_ctf"
  - "iot_ctf"
---

This week I have a very different type of CTF challenge writeup: keyfob. I attended NDIAS Auto/IoT CTF over the last weekend, and ended up solving some keyfob/signals related challenges. These type of challenges are quite rate in CTF, in fact it was the first time I saw it in an online CTF since the start of this year. This was a rare opportunity I couldn't miss, so I had to take a break from pwn challenges this week.

Keyfob was one of the categories in this CTF, I ended up solving 6 out of 8 keyfob challenges. I will publish all challenge writeups here instead of separate entries. They are pretty straightforward, so I believe one post should be enough to cover the 6 challenges I solved. 

## Challenge 1: Parking Lot Whisper

These challenges come with a radio recording of the spectrum of keyfob signals that require understanding of radio signals and how to process them. Keyfobs generally use On OFF keying (OOK) to transmit data, so my first instinct was to look at the spectrum and see if that would apply here. Looking at the waterfall plot of the capture, I found that there were 6 bursts and zoomed into one of them:

![Keyfob OOK](/assets/img/keyfob_ook.png)

Looking at the spectrum, we can see some wait periods, on and off periods of varying durations. This is a very good example of on-off keying modulation. On periods represent one, and off periods represent zero. Shortes period of on or off is probably the symbol duration. Challenge asks us t find **Centre frequency, modulation type and symbol period.** We can from the spectrum that bursts are centred, and we are given that capture is taken at 433.92 mhz, so the centre frequency of bursts are 433920000 hz. And modulation type is OOK. To find the symbol duration/period I used Universal Radio Hacker (URH) and let it auto find it for me:

![Keyfob URH](/assets/img/keyfob_urh1.png)

Just by loading the file it auto detected some parameters like modulation type is ASK. OOK is an simple form of Amplitude Shift Keying (ASK) where we have only two levels on and off. It also predicts that symbol length is 1000 samples, given the 2Msps sampling rate this gives us:

`1000 / 2e6 = 500 microseconds`

To confirm if it is right, zoom into one of the bursts and find the shortest looking on or off duration and select that region:

![Keyfob symbol duration](/assets/img/keyfob_urh2.png)

If you set the sampling rate of the capture in details properly, it should give you the rough duration and number of samples. Looking at the results, we can see roughly 1000 samples and 500 microseconds duration. And with that we got the flag: flag{433920000_OOK_500}

## Challenge 2: Read the Simple Fob

This one is the continuation of the first challene with the same capture file. We are given some clear hints in the challenge description:

```
The file capture_c1c2.bin used in the previous challenge contains a Falcon X1 keyfob signal. 
The Unlock frame of this keyfob is Manchester-encoded. 
Locate a complete Unlock frame in the IQ data, perform Manchester decoding, and analyze the decoded data to recover the Device ID. 
The Device ID is defined as the 3 bytes immediately following the sync word 0xD5.
```

It tells us that it uses Manchester encoding, there is a sync word `0xD5`, and 3 bytes of ID. URH is great at decoding these signals, so I continued from there. Looking back at the full capture in URH, we can see some short noise looking like parts. I simply deleted them to work on the good looking 6 bursts. And then played with decoding parameters in Analysis tab until I got a result with `0xD5`:

![URH decoding](/assets/img/keyfob_urh_decoding.png)

We can see repeating bytes that we call preamble, 0xD5 byte is right after that and some repeating data that is probably the ID and some extra stuff:

```
PREAMBLE  SYNC     ID      REST
  aaaa     d5    7a21cc  2001375a
```

With this simple analysis, we got the flag:  flag{7A21CC}


## Challenge 3: Next Counter

This challenge comes with a new capture file. And this is the challenge description provided:

`Falcon X1 keyfob transmissions from a different device were captured multiple times. Analyze the frames, identify the pattern exhibited by this keyfob, and predict the frame that will be transmitted during the next Unlock action.`

This CTF was the first time I actually properly used URH to decode some signals. After being impressed by its abilities in the first two challenges, I decided to keep going with URH to decode these OOK modulated signals. Again I followed the same steps from the other challenges: load the signal, clean out noisy looking parts and apply manchester decoding:

```
aaaa   d5  9c4e2b  2001  37   5a
aaaa   d5  9c4e2b  2001  37   5a
aaaa   d5  9c4e2b  2001  37   5a
aaaa   d5  9c4e2b  2001  38   5a
aaaa   d5  9c4e2b  2001  38   5a
aaaa   d5  9c4e2b  2001  38   5a
aaaa   d5  9c4e2b  2001  39   5a
aaaa   d5  9c4e2b  2001  39   5a
aaaa   d5  9c4e2b  2001  39   5a
aaaa   d5  9c4e2b  2001  3a   5a
aaaa   d5  9c4e2b  2001  3a   5a
aaaa   d5  9c4e2b  2001  3a   5a
aaaa   d5  9c4e2b  2001  3b   5a
aaaa   d5  9c4e2b  2001  3b   5a
aaaa   d5  9c4e2b  2001  3b   5a
```

Looking at the column just before final byte 0x5A, we can clearly see a counter is increasing by one. Challenge asks for the next open frame which requires us to use next counter. Also looking at the data, we can see that the counter is the only byte that is changing. This confirms that there is no CRC or some form of checksum that we would need to recalculate, so we just increase the counter and we have the next packet: `AAAAD59C4E2B20013C5A` which is the flag of this challenge.

## Challenge 4: Predict Next UNLOCK

This challenge comes with a new capture again. Description:

`Multiple Unlock transmissions from another Falcon X1 keyfob were captured. Analysis of the frames shows that, in addition to the Counter, there is another value that changes between transmissions. Based on the observed pattern, predict the unique valid Unlock frame that will be transmitted next by this keyfob.`

It sounds similar to the third challenge with some more changes. I followed the same decoding steps and I got this data out of it:

```
aaaa d5 b84f62 2002  04 c18b 5a
aaaa d5 b84f62 2002  04 c18b 5a
aaaa d5 b84f62 2002  04 c18b 5a
aaaa d5 b84f62 2002  05 d4c2 5a
aaaa d5 b84f62 2002  05 d4c2 5a
aaaa d5 b84f62 2002  06 e7f9 5a
aaaa d5 b84f62 2002  06 e7f9 5a
aaaa d5 b84f62 2002  06 e7f9 5a
aaaa d5 b84f62 2002  07 fb30 5a
aaaa d5 b84f62 2002  07 fb30 5a
aaaa d5 b84f62 2002  07 fb30 5a
```

As the challenge suggests, in addition to the counter byte there are two more bytes changing this time. To be able to create next packet, we have to know how these values are calculated so we can calculate the next one. After a bit of struggling and trying bit shifts etc. I found that they were increasing by a fixed amount:

```
d4c2 - c18b = 1337  (+0x1337)
e7f9 - d4c2 = 1337  (+0x1337)
fb30 - e7f9 = 1337  (+0x1337)
```

So to create next packet, we need to use next counter `08`, and the next two bytes counter `fb30 + e7f9 = 0e67`. With that we get the next packet and flag: `AAAAD5B84F622002080E675A`

## Challenge 5: Classic KeeLoq Garage: Find the Key

First 4 challenge were classified as easy, now we are moving into medium level challenges. As the title of the challenge suggests, this one involves KeeLoq. KeeLoq is a hardware based block cipher to encrypt rolling codes. Classic indicates that it is the original KeeLoq encryption, not the recent AES based one. Challenge description:

`An RF capture from a garage remote was obtained, and an installer’s note was also recovered at the scene. It was determined that this system uses a classic rolling code scheme. Analyze the RF capture and the note, and recover the 64-bit DeviceKey used by this remote. The synchronization word is the same as in the previous challenges.`

As it is mentioned in the description, we are also provided a note along with the new capture file:

```
<<NDIAS-GARAGE Install Note>>
Model: KG-370
Remote SN: ???
Button map: 0x01 = OPEN
Fixed part: SERIAL(32) || BTN(8)
Legacy derive: K = SEED || (SEED XOR SERIAL)
Seed: 6D3A91C4
Disc bits: lower 10 bits
Learn window: 16
```

We are given most of the details of the key logic in this note actually. But, this challenge actually threw me off a bit initially. Notice how the note mentione 0x01 is for opening, and now look at the received data after decoding it in URH:

```
aaaa d5 913b00d7 01d4a2b700
aaaa d5 913b00d7 01d4a2b700
aaaa d5 913b00d7 01d4a2b700
aaaa d5 0020d1fb 01d4a2b700
aaaa d5 0020d1fb 01d4a2b700
aaaa d5 80ed145b 01d4a2b700
aaaa d5 80ed145b 01d4a2b700
aaaa d5 80ed145b 01d4a2b700
aaaa d5 314c03e4 01d4a2b700
aaaa d5 314c03e4 01d4a2b700
aaaa d5 314c03e4 01d4a2b700
```

A bit of reading about the protocol, and looking at the received data, we can definitely say that the part after the sync word is the encrypted block - 32bits exactly. Reason is simple, that part changes and rest of the packet doesn't. So essentially we get two parts: **encrypted part and fixed part**. Now the confusing part, note was saying  `Fixed part: SERIAL(32) || BTN(8)` taking `||` as concatenation, we need to concatenate button info to serial number. **Looking at the 0x01 in the fixed part, I assumed that was button = open, and it wasn't**

After generating keys based on my assumption and failing with each submission, it finally occured to me that 0x01 was not the button, but **0x00 at the end was the button code!** So as it was shown on the note, button code was concatenated to the end which gives us:

`01d4a2b7 = SN`

And then to find the key:

`K = SEED || (SEED XOR SERIAL)`

`K = 6D3A91C4 || (6D3A91C4 XOR 01d4a2b7)`

`K = 6D3A91C46CEE3373`

And this is the flag for this challenge. My wrong assumption at the beginning led to me losing some time but in the end we got the key. This key will be used in the next challenge. 

## Challenge 6: Classic KeeLoq Garage: Next HOP

We are continuing with the same file and the note from the previous challenge. Now the task is to generate next OPEN signal frame:

```
Using the DeviceKey recovered in Find the Key, analyze the rolling code used by this garage remote. 
The Hop field is encrypted using the standard KeeLoq algorithm. Predict the next valid Open-signal frame. 
The Hop field is a 32-bit Encrypted Hop, and the counter is 16 bits.
```

In terms of what we need to do, the task is simple: use the key from previous challenge and encrypt a new frame. But how do we encrypt it? Answer is, I don't really know :D. At this point, I decided to use Claude to implement the encryption logic to save a bit of time. 

```python
#!/usr/bin/env python3
"""
KeeLoq Decoder/Encoder

Device info:
  Seed   : 0x6D3A91C4
  Serial : 0x01D4A2B7
  Key    : 0x6D3A91C46CEE3373  (SEED || SEED^SERIAL)
  Disc   : 0x2B7  (lower 10 bits of serial)
  BTN    : 0x01 = OPEN
"""

# ── KeeLoq core ──────────────────────────────────────────────────────────────

NLF_LUT = 0x3A5C742E  # 32-entry non-linear function lookup table

def nlf(x):
    """KeeLoq Non-Linear Function using taps at bits 1,9,20,26,31."""
    b0  = (x >> 1)  & 1
    b1  = (x >> 9)  & 1
    b2  = (x >> 20) & 1
    b3  = (x >> 26) & 1
    b4  = (x >> 31) & 1
    idx = b0 | (b1 << 1) | (b2 << 2) | (b3 << 3) | (b4 << 4)
    return (NLF_LUT >> idx) & 1

def keeloq_encrypt(pt, key):
    """Encrypt a 32-bit plaintext with a 64-bit key (528 rounds)."""
    x = pt
    for i in range(528):
        kb = (key >> (i % 64)) & 1
        b  = (x & 1) ^ ((x >> 16) & 1) ^ nlf(x) ^ kb
        x  = (x >> 1) | (b << 31)
    return x

def keeloq_decrypt(ct, key):
    """Decrypt a 32-bit ciphertext with a 64-bit key (528 rounds reversed)."""
    x = ct
    for i in range(527, -1, -1):
        kb      = (key >> (i % 64)) & 1
        tmp     = (x << 1) & 0xFFFFFFFF   # reconstruct old state (bit0 unknown, nlf ignores it)
        nlf_val = nlf(tmp)
        b0      = ((x >> 31) & 1) ^ ((x >> 15) & 1) ^ nlf_val ^ kb
        x       = ((x << 1) & 0xFFFFFFFF) | b0
    return x

# ── Key derivation ────────────────────────────────────────────────────────────

def derive_key(seed, serial):
    """Legacy KeeLoq key derivation: K = SEED || (SEED XOR SERIAL)."""
    return ((seed & 0xFFFFFFFF) << 32) | ((seed ^ serial) & 0xFFFFFFFF)

# ── Plaintext layout ──────────────────────────────────────────────────────────
#
#  [31:22]  discriminator (10 bits) = lower 10 bits of serial  ← MSB side
#  [21:8]   zeros / status
#  [7:0]    counter (low byte, increments per press)
#
# Fixed part layout (40-bit, transmitted in plaintext):
#  [39:8]   serial (32 bits)
#  [7:0]    button code (8 bits)  0x01 = OPEN

def parse_plaintext(pt, serial):
    disc     = (pt >> 22) & 0x3FF
    counter  = pt & 0xFF
    disc_exp = serial & 0x3FF
    disc_ok  = disc == disc_exp
    return {
        "raw":      hex(pt),
        "disc":     hex(disc),
        "disc_ok":  disc_ok,
        "counter":  hex(counter),
    }

def build_plaintext(serial, counter, btn_in_hopping=0x0):
    """
    Build the 32-bit hopping code plaintext.
    disc      = lower 10 bits of serial  → placed at [31:22]
    btn       = button nibble            → placed at [11:8]  (optional, 0 if not used)
    counter   = press counter            → placed at [7:0]
    """
    disc = (serial & 0x3FF) << 22
    btn  = (btn_in_hopping & 0xF) << 8
    ctr  = counter & 0xFF
    return disc | btn | ctr

# ── High-level helpers ────────────────────────────────────────────────────────

def decode_frame(hopping_ct, fixed_hex, seed, serial):
    """Decode a full KeeLoq frame."""
    key    = derive_key(seed, serial)
    pt     = keeloq_decrypt(hopping_ct, key)
    parsed = parse_plaintext(pt, serial)
    btn    = int(fixed_hex[-2:], 16)
    return {
        "hopping_ct":  f"{hopping_ct:08x}",
        "plaintext":   parsed,
        "fixed_btn":   f"0x{btn:02x}",
        "btn_is_open": btn == 0x01,
    }

def encode_frame(seed, serial, counter, btn_fixed=0x01, btn_hopping=0x0):
    """Encode the next KeeLoq OPEN frame."""
    key    = derive_key(seed, serial)
    pt     = build_plaintext(serial, counter, btn_hopping)
    ct     = keeloq_encrypt(pt, key)
    fixed  = f"{serial:08x}{btn_fixed:02x}"
    return {
        "plaintext":   f"{pt:08x}",
        "hopping_ct":  f"{ct:08x}",
        "fixed":       fixed,
        "full_frame":  f"{ct:08x} {fixed}",
    }

def encode_frame2(seed, serial, pt, fixed):
    """Encode the next KeeLoq OPEN frame."""
    key    = derive_key(seed, serial)
    ct     = keeloq_encrypt(pt, key)
    return {
        "plaintext":   f"{pt:08x}",
        "hopping_ct":  f"{ct:08x}",
        "fixed":       fixed,
        "full_frame":  f"{ct:08x} {fixed}",
    }

# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SEED   = 0x6D3A91C4
    SERIAL = 0x01D4A2B7
    KEY    = derive_key(SEED, SERIAL)

    print("=" * 60)
    print("KeeLoq CTF Decoder")
    print("=" * 60)
    print(f"  Seed   : {SEED:#010x}")
    print(f"  Serial : {SERIAL:#010x}")
    print(f"  Key    : {KEY:#018x}")
    print(f"  Disc   : {SERIAL & 0x3FF:#05x}")
    print()

    # ── Decode known captures ────────────────────────────────────
    captures = [
        (0x913b00d7, "01d4a2b700"),
        (0x0020d1fb, "01d4a2b700"),
        (0x80ed145b, "01d4a2b700"),
        (0x314c03e4, "01d4a2b700"),
        (0x65317adf, "01d4a2b700"),
    ]

    print("── Captured frames ──────────────────────────────────────")
    for ct, fixed in captures:
        r = decode_frame(ct, fixed, SEED, SERIAL)
        disc_sym = "✓" if r["plaintext"]["disc_ok"] else "✗"
        print(f"  CT={r['hopping_ct']}  PT={r['plaintext']['raw']}"
              f"  DISC={disc_sym}  CNT={r['plaintext']['counter']}"
              f"  BTN_fixed={r['fixed_btn']}")
    print()

    # ── Predict next frames ──────────────────────────────────────
    print("── Next predicted OPEN frames ───────────────────────────")

    r = encode_frame2(SEED, SERIAL, pt=0xadc40044, fixed = '01d4a2b701')
    print(f"    PT         : {r['plaintext']}")
    print(f"    Full frame : {r['full_frame']}")
```

I got Claude to write to code, but I had to do some reversing to understand the frame logic. Now I used this code to decode the encrypted frames we received:

```
  CT=913b00d7  PT=0xadc40040  DISC=✓  CNT=0x40  BTN_fixed=0x00
  CT=0020d1fb  PT=0xadc40041  DISC=✓  CNT=0x41  BTN_fixed=0x00
  CT=80ed145b  PT=0xadc40042  DISC=✓  CNT=0x42  BTN_fixed=0x00
  CT=314c03e4  PT=0xadc40043  DISC=✓  CNT=0x43  BTN_fixed=0x00
```

CT is the cypher text - encrypted frames we received in the decoded capture file. PT is the plaintext - decrypted frames. DISC is just a check to see if the decrypted frames contain the expected 10 bits discriminator. This gives us roughly this layout we can use to generate new packets:

```
 Plaintext layout

  [31:22]  discriminator (10 bits) = lower 10 bits of serial  ← MSB side
  [21:8]   zeros / status
  [7:0]    counter (low byte, increments per press)

 Fixed part layout (40-bit, transmitted in plaintext):
  [39:8]   serial (32 bits)
  [7:0]    button code (8 bits)  0x01 = OPEN
```


While trying to solve the 5th challenge, I had issues figuring out where the button info were going. Since I confirmed the serial part, we can safely say button state is the last byte, so fixed bytes - the part that doesn't go through encryption - should be `01d4a2b701`. 

Next question I had was should button state be part of the encrypted part? Answer was no. In previous packets we had button state = 0x00, but none of the decoded bytes were 0x00! So it indicates button state wasn't part of the encrypted portion. With this logic we end up with `0xadc40044` plain text where we increased the counter byte and kept the rest same.

And now we decided on what the frame is carrying, I just used the script to encrypt the frame and get the next hop packet:

```
    PT         : adc40044
    Full frame : 65317adf 01d4a2b701
```

## Final Notes

I didn't have a chance to look at the final two challenges of keyfob category unfortunately due to time constraints. This CTF had another signals related challenge. I tried to solve that one and got very close to result but couldn't. I might do another writeup for that challenge if I can find some time, it deserves its own writeup. 

I personally love signals and radio related challenges, decoding packets, analyzing them and extracting information out of them. I wish we get more CTFs like this one. Thanks to keyfob challenges, I finally get to play with URH first time. It looks like it is a great tool for such signals. I will finish this writeup here, I don't think I will update this for the other two keyfob challenges if I ever go back to them. See you on the next one and as always, keep learning!