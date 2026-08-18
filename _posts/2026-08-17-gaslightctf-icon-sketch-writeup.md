---
title: "GaslightCTF: Icon Sketch Forensics Writeup"
date: 2026-08-17
categories: 
  - "forensics"
  - "steganography"
tags: 
  - "stego"
  - "ctf"
  - "gaslightctf"
  - "forensic"
  - "steganography"
---

Surprise, I decided to bring you a non-pwn writeup for a change. In recent CTFs I have been looking at forensics challenges involving Steganography with image, audio and video files. This challenge `Icon-sketch` is an image steganography challenge from Gaslight CTF 2026. Well to be honest, it is more like a Misc/Crypto challenge if you ask me, but it is what it is. Let's see how I solved this challenge.

## Handout

We are given this png file, hopefully metadata isn't destroyed here:

![Handout Image](/assets/img/gaslight_icon.png)

Next thing is to look at metadata, use an online tool like <https://exif.tools/> or `exiftool` app and look at unusual text in description, title, other fields etc. These 3 stood out to me:

```
Document name = dGhlIHBlZSBwZW9wbGUgc2FpZCB0byBkZWNvZGUgYW5kIHB1dCB0aGUgdGl0bGVzIHRvZ2V0aGVy
Title         = dHpob3J0c2cuLi57cjUuZy4uZy5oZi4uLi4ud18uLi5rLi5oPy4=
ArtworkTitle  = MmUgMmUgMmUgMmUgMmUgMmUgMmUgMmUgNDMgNTQgNDYgMmUgMmUgMmUgNWYgMmUgNjggMzQgMmUgNWYgMmUgMmUgNzAgNzAgMzAgNzMgMzMgMmUgMmUgMzIgNjIgNWYgMmUgMzEgNzMgMmUgMmUgN2Q=
```

After that I also tried `zsteg` to see if there is anything unusual, like LSB stego etc but it didn't flag anything other than the title field already mentioned above.

## Decode Document Name

This one was quite straightforward, just base64 decode:

```
import base64

document_name = 'dGhlIHBlZSBwZW9wbGUgc2FpZCB0byBkZWNvZGUgYW5kIHB1dCB0aGUgdGl0bGVzIHRvZ2V0aGVy'
decoded_str   = base64.b64decode(document_name).decode("utf-8")
print(decoded_str)
```

This gives us the decoded text: `the pee people said to decode and put the titles together`. Sounds like an important clue where we need to combine titles.

## Decode Title

This one also looked like base64 encoded, decoding it with base64 gives us this flag looking string:

`tzhortsg...{r5.g..g.hf.....w_...k..h?.`

If you can notice, beginning part has the same length as `gaslight` and probably the following three dots is `CTF` making up the flag's prefix. How do we convert this to `gaslight` ? If you align them:

```
tzhortsg
gaslight
```

Notice the changes: `t->g  g->t  a->z`, specially a to z change indicates reversal of alphabet which is called `Atbash`. To decode it, we simply translate lower case letters to their reverse order and ignore numbers or dots:

```python
def atbash_decoder(text: str) -> str:
    # Map letters to their reversed counterparts
    lower_abc = "abcdefghijklmnopqrstuvwxyz"
    translation_table = str.maketrans(lower_abc, lower_abc[::-1])
    return text.translate(translation_table)

title = 'dHpob3J0c2cuLi57cjUuZy4uZy5oZi4uLi4ud18uLi5rLi5oPy4='
b64_decoded = base64.b64decode(title).decode("utf-8")
part1 = atbash_decoder(b64_decoded)
print(part1)    
```

And this gives us one piece of the puzzle: `gaslight...{i5.t..t.su.....d_...p..s?.`

## Decode Artwork Title

Given the hint and previous result, this should give us the missing letters/dots of the flag. Again we first base64 decode it and it gives us this result:

`2e 2e 2e 2e 2e 2e 2e 2e 43 54 46 2e 2e 2e 5f 2e 68 34 2e 5f 2e 2e 70 70 30 73 33 2e 2e 32 62 5f 2e 31 73 2e 2e 7d`

It is a string of hexadecimal numbers, we just need to conver it to a string:

```python
artwork_title = 'MmUgMmUgMmUgMmUgMmUgMmUgMmUgMmUgNDMgNTQgNDYgMmUgMmUgMmUgNWYgMmUgNjggMzQgMmUgNWYgMmUgMmUgNzAgNzAgMzAgNzMgMzMgMmUgMmUgMzIgNjIgNWYgMmUgMzEgNzMgMmUgMmUgN2Q='
b64_decoded = base64.b64decode(artwork_title).decode("utf-8")
part2 = bytes.fromhex(b64_decoded).decode('utf-8')
print(part2)
```

And this gives us the second part of the flag: `........CTF..._.h4._..pp0s3..2b_.1s..}` 

## Combine Parts

We just need to combine two parts to get the final flag:

```python
# Combine by picking the character that is not a dot '.'
flag = "".join(c1 if c1 != '.' else c2 for c1, c2 in zip(part1, part2))
print(flag)
```

And we get the flag: `gaslightCTF{i5_th4t_supp0s3d_2b_p1ss?}`. 

## Final Script

Here is the full script combining all these steps:

```python
import base64

def atbash_decoder(text: str) -> str:
    # Map letters to their reversed counterparts
    lower_abc = "abcdefghijklmnopqrstuvwxyz"
    translation_table = str.maketrans(lower_abc, lower_abc[::-1])
    return text.translate(translation_table)

# the pee people said to decode and put the titles together
document_name = 'dGhlIHBlZSBwZW9wbGUgc2FpZCB0byBkZWNvZGUgYW5kIHB1dCB0aGUgdGl0bGVzIHRvZ2V0aGVy'
decoded_str   = base64.b64decode(document_name).decode("utf-8")
print(decoded_str)

title = 'dHpob3J0c2cuLi57cjUuZy4uZy5oZi4uLi4ud18uLi5rLi5oPy4='
b64_decoded = base64.b64decode(title).decode("utf-8")
part1 = atbash_decoder(b64_decoded)
print(part1)

artwork_title = 'MmUgMmUgMmUgMmUgMmUgMmUgMmUgMmUgNDMgNTQgNDYgMmUgMmUgMmUgNWYgMmUgNjggMzQgMmUgNWYgMmUgMmUgNzAgNzAgMzAgNzMgMzMgMmUgMmUgMzIgNjIgNWYgMmUgMzEgNzMgMmUgMmUgN2Q='
b64_decoded = base64.b64decode(artwork_title).decode("utf-8")
part2 = bytes.fromhex(b64_decoded).decode('utf-8')
print(part2)

# Combine by picking the character that is not a dot '.'
flag = "".join(c1 if c1 != '.' else c2 for c1, c2 in zip(part1, part2))
print(flag)
```

Nice challenge, during the CTF I actually used CyberChef: <https://gchq.github.io/CyberChef/> to decode all these steps :) It is much easier and faster that way, script was just a challenge to myself to see how I would solve it in python. My suggestion, use CyberChef it is amazing. As always, keep learning!
