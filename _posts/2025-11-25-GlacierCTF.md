---
title: "GlacierCTF Rev Writeup"
date: 2025-11-25 14:00:00 +0800
categories: [CTF]
tags: [Reverse Engineering]
image:
  path: assets/CTF.png
  show_in_post: false
---

---
## **Wisdom**

<div style="text-align: center;">
  <img src="/assets/GlacierCTF/image.png" alt="Challenge Description" width="450" style="border-radius:16px;">
</div>

<div style="font-size:1.5em; font-weight:bold; margin-top:20px; margin-bottom:10px;">
  Initial Analysis
</div>

We are given a 64-bit ELF binary that prompts the user for “wisdom” and validates the input.  
The binary is dynamically linked and unstripped, making reverse engineering easier.

<div style="font-size:1.5em; font-weight:bold; margin-top:20px; margin-bottom:10px;">
  Static Analysis
</div>

After tossing the binary into Ghidra, things start to make sense.

<div style="font-size:1.5em; font-weight:bold; margin-top:20px; margin-bottom:10px;">
  Main Function
</div>

The main function reads exactly 46 bytes (`0x2e`) and passes them to a verification function:

<div style="text-align: center;">
  <img src="/assets/GlacierCTF/image (1).png" alt="Main Function" width="450" style="border-radius:16px;">
</div>

<div style="font-size:1.5em; font-weight:bold; margin-top:20px; margin-bottom:10px;">
  check_flag() Function
</div>

All the core logic happens inside `check_flag()`.  
It transforms each character using a KEY, the index, and a MAGIC constant:

<div style="text-align: center;">
  <img src="/assets/GlacierCTF/image (2).png" alt="Check Flag Function" width="450" style="border-radius:16px;">
</div>

The transformation is:

```
transformed[i] = ((input[i] ^ KEY[i]) - i) + MAGIC
```

<div style="font-size:1.5em; font-weight:bold; margin-top:20px; margin-bottom:10px;">
  Extracted Data
</div>

These are the values extracted from the binary:

<div style="font-size:1.5em; font-weight:bold; margin-top:20px; margin-bottom:10px;">
  KEY (46 bytes)
</div>

```
36 d1 d9 db 89 a5 be de 5e e6 0f 12 02 1a e1 c0 0b 4c a3 b0 08 e9 a0 d0 d1 ea 88 71 23 87 d0 41 d8 04 09 a2 fd 20 02 28 0d 75 8d 66 a8 5c
```

<div style="font-size:1.5em; font-weight:bold; margin-top:20px; margin-bottom:10px;">
  FLAG (46 bytes)
</div>

```
af 0f 09 18 4c 47 33 44 64 0e bc 75 bd a5 d6 ee a0 c9 22 3a b9 cf 3c d6 eb e7 fd 45 be f8 20 b0 2b 6e a7 fe 02 49 73 84 a2 78 f0 88 c2 52
```

<div style="font-size:1.5em; font-weight:bold; margin-top:20px; margin-bottom:10px;">
  MAGIC
</div>

<div style="text-align: center;">
  <img src="/assets/GlacierCTF/image (3).png" alt="Magic Value" width="300" style="border-radius:16px;">
</div>


```
0x5e (only the least significant byte is used)
```

<div style="font-size:1.5em; font-weight:bold; margin-top:20px; margin-bottom:10px;">
  Solutions
</div>

To find the correct input, we need to reverse the transformation. The algorithm in the `check_flag` function can be reversed as follows:

For each position `i`:

```
input[i] = ((FLAG[i] - MAGIC + i) ^ KEY[i])
```

<div style="font-size:1.5em; font-weight:bold; margin-top:20px; margin-bottom:10px;">
  Solutions Script
</div>

```python
KEY = bytes([
    0x36, 0xd1, 0xd9, 0xdb, 0x89, 0xa5, 0xbe, 0xde, 0x5e, 0xe6,
    0x0f, 0x12, 0x02, 0x1a, 0xe1, 0xc0, 0x0b, 0x4c, 0xa3, 0xb0,
    0x08, 0xe9, 0xa0, 0xd0, 0xd1, 0xea, 0x88, 0x71, 0x23, 0x87,
    0xd0, 0x41, 0xd8, 0x04, 0x09, 0xa2, 0xfd, 0x20, 0x02, 0x28,
    0x0d, 0x75, 0x8d, 0x66, 0xa8, 0x5c
])

FLAG = bytes([
    0xaf, 0x0f, 0x09, 0x18, 0x4c, 0x47, 0x33, 0x44, 0x64, 0x0e,
    0xbc, 0x75, 0xbd, 0xa5, 0xd6, 0xee, 0xa0, 0xc9, 0x22, 0x3a,
    0xb9, 0xcf, 0x3c, 0xd6, 0xeb, 0xe7, 0xfd, 0x45, 0xbe, 0xf8,
    0x20, 0xb0, 0x2b, 0x6e, 0xa7, 0xfe, 0x02, 0x49, 0x73, 0x84,
    0xa2, 0x78, 0xf0, 0x88, 0xc2, 0x52
])

MAGIC = 0x5e

def solve():
    result = []
    for i in range(46):
        # Reverse the transformation: input[i] = ((FLAG[i] - MAGIC + i) ^ KEY[i])
        val = (FLAG[i] - MAGIC + i) & 0xFF  # Ensure byte range uint8
        val = val ^ KEY[i]
        result.append(val)
    return bytes(result)

if __name__ == "__main__":
    solution = solve()
    print(f"Flag: {solution.decode()}")
```

<div style="font-size:1.5em; font-weight:bold; margin-top:20px; margin-bottom:10px;">
  Flag
</div>

Running the solution script reveals the flag:

```
Flag: gctf{Ke3P_g0iNg_Y0u_goT_tH1s_00055ba509ea6138}
```
---