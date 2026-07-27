# The Cinder Engine — Reverse Engineering Writeup

**Category:** Reversing
**Flag:** `HTB{c1nd3r_3ng1n3_unw0und}`

> *"Work out its opcode map from how it moves. Pull the firmware apart and find the cipher hiding in its tables. Then feed it something worth saying."*

The prompt is an unusually honest roadmap. It tells you there are exactly three phases: recover the instruction set of a custom VM, recover the cipher its bytecode implements, and invert that cipher. This writeup follows those three phases in order.

---

## TL;DR

`cinder` is a stripped AArch64 binary containing a hand-rolled 4-byte-instruction VM. Its firmware lives in `.rodata` and implements an 8-round substitution–permutation network over a 32-byte block. The S-box is a real permutation and the diffusion layer is an invertible 32×32 matrix over GF(2), so the whole construction runs backwards. Inverting it from the stored target ciphertext yields the 32-byte input; the engine then prints the flag as `firmware_mask XOR your_input`, so the flag only appears if the input is bit-exact.

---

## Phase 0 — Recon

```
$ unzip the_cinder_engine.zip
$ file cinder
cinder: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV),
        dynamically linked, interpreter /lib/ld-linux-aarch64.so.1,
        BuildID[sha1]=b329..., for GNU/Linux 3.7.0, stripped
```

AArch64, PIE, stripped. The `.DS_Store` in the archive is packaging noise — it contains only Finder layout blobs, no challenge data.

Two things immediately shape the approach. First, the import list is tiny:

```
getc  putc  fwrite  stdin  stdout  stderr  abort  __stack_chk_fail
```

No `open`, no `socket`, no `time`. Everything happens on stdin/stdout with data already inside the file.

Second, and more telling, the section sizes are inverted from a normal program:

| Section | Address | Size |
|---|---|---|
| `.text` | `0x880` | `0x5d4` (1492 B) |
| `.rodata` | `0xe68` | `0x1336` (4918 B) |
| `.bss` | `0x13010` | `0x10048` (64 KB) |

Three and a half times more read-only data than code, plus a 64 KB zeroed region. Combined with the string `bad opcode`, this is the signature of an interpreter: the small `.text` is the dispatch loop, the large `.rodata` is the program it runs, and `.bss` is that program's RAM.

So: don't reverse the binary looking for a check. Reverse the binary to learn the *language*, then reverse the program written in it.

---

## Phase 1 — Recovering the opcode map

Since the host is AArch64 and I was on x86-64, I used Capstone rather than a cross-objdump:

```python
from capstone import *
data = open('cinder','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
for i in md.disasm(data[0x880:0x880+0x5d4], 0x880):
    print("%06x:\t%-10s %s" % (i.address, i.mnemonic, i.op_str))
```

*(Watch out: naming that script `dis.py` shadows the CPython stdlib `dis` module that Capstone imports transitively, and you get a confusing circular-import error. Name it anything else.)*

### 1a. Setup and the fetch cycle

The prologue reads input and establishes the machine's context:

```
0008cc: b     #0x8e0          ; read loop: getc() until EOF or 4096 bytes
0008d0: add   w22, w22, #1    ; w22 = input length
0008d4: strb  w0, [x20], #1   ; into stack buffer at sp+8
...
0008f0: adrp  x23, #0x13000
0008f8: add   x23, x23, #0x18 ; x23 = 0x13018  -> register file
0008f4: adrp  x21, #0
0008fc: add   x21, x21, #0xe80; x21 = 0xe80    -> FIRMWARE BASE
00091c: mov   w25, #0x131e    ; w25 = 0x131e   -> firmware length
```

That `0xe80` is the important find. `.rodata` starts at `0xe68`, and the 24 bytes before `0xe80` hold the `bad opcode\n` string. So the firmware occupies `0xe80 .. 0x219e`, and `0x1336 - 0x18 = 0x131e` confirms the length register.

The fetch tail sits at `0x9a8` and every handler jumps back to it:

```
0009a8: add   w1, w20, #1
0009ac: add   w2, w20, #2
0009b0: add   w0, w20, #3
0009b4: ldrb  w3, [x21, w20, uxtw]   ; b0
0009b8: ldrb  w1, [x21, w1, uxtw]    ; b1
0009bc: ldrb  w2, [x21, w2, uxtw]    ; b2
0009c0: ldrb  w0, [x21, w0, uxtw]    ; b3
0009c4: b     #0x920
```

Four bytes at a time, so instructions are fixed-width 4 bytes and `w20` is the program counter (byte-granular).

### 1b. The instruction format

The decode block at `0x920` is where the format falls out:

```
000920: lsl   w2, w2, #0x10          ; b2 << 16
000924: orr   w0, w3, w0, lsl #24    ; b0 | (b3 << 24)
000928: orr   w1, w2, w1, lsl #8     ; (b2 << 16) | (b1 << 8)
00092c: add   w20, w20, #4           ; pc += 4
000930: orr   w2, w1, w0             ; w2 = full little-endian word
000934: lsr   w0, w0, #0x18          ; OPCODE = b3
000938: orr   w3, w2, #0xffff0000
00093c: and   w5, w2, #0xffff        ; imm16 (zero-extended)
000940: tst   x2, #0x8000
000944: and   w6, w2, #0xf           ; rb = low nibble
000948: csel  w4, w3, w5, ne         ; imm16 sign-extended
00094c: ubfx  x3, x1, #0x14, #4      ; rd = high nibble of b2
000950: ubfx  x1, x1, #0x10, #4      ; ra = low nibble of b2
```

The word is assembled little-endian, but the opcode is extracted from bit 24 upward — the **most significant** byte. On disk that means the bytes read `[imm_lo][imm_hi][rd:ra][opcode]`, with the opcode *last*. That's a small but effective trap: anyone who eyeballs the firmware hex assuming the first byte is the opcode will get nonsense.

Final layout:

```
 31      24 23   20 19   16 15                    0
+----------+-------+-------+-----------------------+
|  opcode  |  rd   |  ra   |        imm16          |
+----------+-------+-------+-----------------------+
                                              rb = imm16 & 0xf
```

Three operand encodings share one word: register-triple ops use `rb`, immediate ops use `imm16`, and branches use `imm16` sign-extended as a PC-relative byte offset applied *after* the increment.

Machine state, collected from the register usage:

| | |
|---|---|
| `R[0..15]` | 32-bit registers at `0x13018` |
| `MEM` | 64 KB byte RAM at `0x13058`, addresses masked `& 0xffff` |
| `w26` | single zero/equality flag |
| `w20` | program counter |
| `w22` / `w24` | input length / input read cursor |
| `x21` / `w25` | firmware base / firmware length |

### 1c. The dispatch tree

The handler table is not a jump table — GCC compiled a `switch` over sparse constants into a binary search:

```
000954: cmp   w0, #0x7c
000958: b.eq  #0xb80
00095c: b.hi  #0xa30
000960: cmp   w0, #0x2c
000964: b.eq  #0xcfc
000968: b.ls  #0x9fc
...
000cb4: <default>  fwrite("bad opcode\n", 1, 11, stderr); return 1
```

This is the "opcode map the scribe kept in his head." The values are scattered across the byte range specifically so you cannot guess them — there is no `0x01 = ADD` convention to fall back on. You have to walk every branch of the tree to its handler and read what the handler does.

Doing that for all 22 leaves:

| Op | Mnemonic | Semantics |
|---|---|---|
| `00` | `HALT` | return 0 |
| `11` | `MOV` | `R[rd] = R[ra]` |
| `29` | `ROL` | `R[rd] = R[ra] <<< (word & 31)` — via `neg` then `ror` |
| `2a` | `ROR` | `R[rd] = R[ra] >>> (word & 31)` |
| `2b` | `SHL` | `R[rd] = R[ra] << (word & 31)` |
| `2c` | `SHR` | `R[rd] = R[ra] >> (word & 31)` logical |
| `3a` | `LDI` | `R[rd] = imm16` |
| `52` | `XOR` | `R[rd] = R[ra] ^ R[rb]`; flag = `R[ra] == R[rb]` |
| `53` | `AND` | `R[rd] = R[ra] & R[rb]`; flag = result == 0 |
| `54` | `OR` | `R[rd] = R[ra] \| R[rb]`; flag = result == 0 |
| `6b` | `MUL` | `R[rd] = R[ra] * R[rb]`; flag = result == 0 |
| `7c` | `ADD` | `R[rd] = R[ra] + R[rb]`; flag = result == 0 |
| `7d` | `SUB` | `R[rd] = R[ra] - R[rb]`; flag = result == 0 |
| `80` | `ADDI` | `R[rd] = R[ra] + imm16`; flag = result == 0 |
| `90` | `CMP` | flag = `R[ra] == R[rb]` |
| `a0` | `JMP` | `pc += simm16` |
| `a1` | `JT` | if flag: `pc += simm16` |
| `a2` | `JF` | if !flag: `pc += simm16` |
| `c4` | `LDB` | `R[rd] = MEM[(R[ra] + imm16) & 0xffff]` |
| `c5` | `STB` | `MEM[(R[ra] + imm16) & 0xffff] = R[rd] & 0xff` |
| `c6` | `LDFW` | `R[rd] = FIRMWARE[(imm16 + R[ra]) % 0x131e]` |
| `e0` | `GETC` | if input remains: `R[rd] = next byte`, flag = 0; else `R[rd] = 0`, flag = 1 |
| `e1` | `PUTC` | `putc(R[ra] & 0xff, stdout)` |

Two handlers deserve attention.

**`c6 LDFW`** lets the bytecode read its own image as data, with the address reduced modulo the firmware length:

```
000c74: add   w5, w5, w0        ; imm16 + R[ra]
000c78: udiv  w0, w5, w25
000c7c: msub  w0, w0, w25, w5   ; % 0x131e
000c80: ldrb  w0, [x21, x0]
```

This is the literal "cipher hiding in its tables" — the constants aren't in a separate data blob, they're addressed as part of the same firmware image the interpreter executes.

**`29 ROL`** is implemented as `neg w2, w2; ror w0, w0, w2`, exploiting the fact that AArch64 masks the shift amount to 5 bits, so rotating right by `-n` is rotating left by `n`. Worth noting because it's easy to mis-model in an emulator.

### 1d. Sanity check

With the map above I wrote a disassembler (`vmdis.py`) and ran it over the firmware. The decode is either right or it isn't, and the histogram answers that instantly:

```
508 LDB    472 XOR    38 STB    16 LDI    11 CMP
 10 ADDI     9 JF      5 LDFW    2 SUB     2 HALT
```

Every instruction from `0x0000` to `0x10c3` decodes to a valid opcode with sensible operands; from `0x10c4` onward, nothing decodes. That clean boundary is both a confirmation of the opcode map and a free discovery: **code occupies `0x0000–0x10c3`, data occupies `0x10c4–0x131d`.**

---

## Phase 2 — Reading the firmware

The disassembled bytecode is short and completely unobfuscated once decoded.

### 2a. Input handling

```
0000: LDI   r0, #0x0000
0004: LDI   r8, #0x0020        ; loop bound = 32
0008: LDI   r4, #0x0000
000c: GETC  r5
0010: STB   [r4 + 0x0000], r5  ; working state at MEM[0x00]
0014: STB   [r4 + 0x0040], r5  ; pristine copy at MEM[0x40]
0018: ADDI  r4, r4, #0x0001
001c: CMP   r4, r8
0020: JF    0x000c
```

Exactly 32 bytes are consumed, and a **second untouched copy is stashed at `MEM[0x40]`**. Nothing in the transformation code ever touches `0x40..0x5f`, which means it exists purely for the endgame. Flag that mentally — it matters in step 2e.

### 2b. Initial key addition

```
0024: LDI   r7, #0x11c4        ; key pointer
0028: LDI   r4, #0x0000
002c: ADD   r9, r7, r4
0030: LDFW  r1, FW[r9 + 0x0000]
0034: LDB   r5, [r4 + 0x0000]
0038: XOR   r5, r5, r1
003c: STB   [r4 + 0x0000], r5
...
004c: ADDI  r7, r7, #0x0020    ; advance one 32-byte round key
0050: LDI   r6, #0x0001        ; round counter = 1
```

Whitening XOR with 32 bytes at firmware offset `0x11c4`, then the key pointer advances by `0x20`.

### 2c. The round function

The main loop runs from `0x0054` to `0x1064`. Three stages:

**Substitution** — a straight table lookup, table at `0x10c4`:

```
0058: LDB   r5, [r4 + 0x0000]
005c: LDFW  r5, FW[r5 + 0x10c4]
0060: STB   [r4 + 0x0000], r5
```

**Diffusion** — 32 unrolled blocks, one per output byte, each XORing a subset of the current state into `MEM[0x80 + j]`:

```
0070: LDB   r5, [r0 + 0x0000]
0074: LDB   r1, [r0 + 0x0001]
0078: XOR   r5, r5, r1
007c: LDB   r1, [r0 + 0x0003]
0080: XOR   r5, r5, r1
      ... 8 more taps ...
00c4: STB   [r0 + 0x0080], r5     ; out[0] = in[0]^in[1]^in[3]^in[6]^in[7]
                                  ;        ^ in[9]^in[16]^in[18]^in[19]
                                  ;        ^ in[25]^in[28]
```

This is where the 508 `LDB` / 472 `XOR` instructions go, and it looks intimidating in bulk. It isn't. Each output is an XOR of a fixed subset of inputs, computed into a scratch region so all 32 outputs depend on the *original* state — that is exactly a matrix–vector product over GF(2), written out longhand. Results are copied back at `0x1018`.

**Key addition** — XOR the next 32-byte round key, bump the pointer and counter:

```
1054: ADDI  r7, r7, #0x0020
1058: ADDI  r6, r6, #0x0001
105c: LDI   r12, #0x0009
1060: CMP   r6, r12
1064: JF    0x0054               ; rounds 1..8
```

So the construction is a clean SPN:

```
state = input ⊕ RK₀
repeat 8×:
    state = SBOX[state]          (bytewise)
    state = M · state            (32×32 over GF(2))
    state = state ⊕ RKᵣ
```

### 2d. Verification

```
1068: LDI   r11, #0x0000
1070: LDFW  r1, FW[r4 + 0x12e4]
1074: LDB   r5, [r4 + 0x0000]
1078: CMP   r5, r1
107c: JT    0x1084
1080: LDI   r11, #0x0001         ; sticky mismatch flag
```

Compare the final state against 32 bytes at `0x12e4`. Note it's a non-short-circuiting compare that sets a sticky flag, so there's no timing side channel to exploit here.

### 2e. The output stage — and why patching fails

```
1098: JF    0x10c0               ; any mismatch -> straight to HALT
109c: LDI   r4, #0x0000
10a0: LDI   r8, #0x001a          ; 26 bytes
10a4: LDFW  r1, FW[r4 + 0x1304]  ; mask from firmware
10a8: LDB   r5, [r4 + 0x0040]    ; ORIGINAL INPUT copy
10ac: XOR   r5, r5, r1
10b0: PUTC  r5
```

This is the challenge's real defence. The flag is **never stored anywhere**. It's emitted as `FW[0x1304 + i] XOR original_input[i]`. Patching the comparison at `0x1098` to always succeed just makes the engine print 26 bytes of garbage keyed by whatever you typed. You cannot bypass the check; you have to *solve* it.

### 2f. The data layout falls out

Everything after `0x10c4` now has a purpose, and the offsets tile perfectly:

| Offset | Size | Contents |
|---|---|---|
| `0x10c4` | 256 | S-box |
| `0x11c4` | 9 × 32 = 288 | Round keys RK₀…RK₈ |
| `0x12e4` | 32 | Target ciphertext |
| `0x1304` | 26 | Flag mask |
| `0x131e` | — | End of firmware |

`0x11c4 + 0x120 = 0x12e4` and `0x1304 + 26 = 0x131e` exactly. No slack, no decoys.

---

## Phase 3 — Inverting the cipher

Three questions decide whether this is invertible.

**Is the S-box a permutation?**

```python
sbox = list(fw[0x10c4:0x10c4+256])
assert sorted(sbox) == list(range(256))   # True
```

Yes — so `S⁻¹` exists as a plain inverse lookup table.

**Is the diffusion matrix invertible?** I recovered it by parsing the instruction stream rather than transcribing by hand — the unrolled block has a rigid shape, so a small state machine over the decoded instructions is exact and instant:

```python
pc = 0x0070
while pc < 0x1018:
    w = struct.unpack_from('<I', fw, pc)[0]
    op, rd, ra, imm, rb = (w>>24)&0xff, (w>>20)&0xf, (w>>16)&0xf, w&0xffff, w&0xf
    if op == 0xc4:                       # LDB
        if rd == 5:   cur = 1 << imm     # start row with this source
        elif rd == 1: pending = imm      # tap to be XORed
    elif op == 0x52:                     # XOR r5, r5, r1
        cur ^= 1 << pending
    elif op == 0xc5:                     # STB [r0 + 0x80+j], r5
        rows[imm - 0x80] = cur
    pc += 4
```

Each row becomes a 32-bit mask of which input bytes feed that output. Row weights come out between 11 and 20 taps, averaging ~15.7 — roughly half of 32, i.e. a dense, well-mixed matrix rather than something sparse and structured.

Then Gauss–Jordan on `[M | I]` over GF(2), using integers as bit-vectors:

```python
A = [rows[j] | (1 << (32 + j)) for j in range(32)]
for c in range(32):
    p = next(k for k in range(c, 32) if A[k] >> c & 1)   # no pivot -> singular
    A[c], A[p] = A[p], A[c]
    for k in range(32):
        if k != c and (A[k] >> c & 1):
            A[k] ^= A[c]
inv = [A[c] >> 32 for c in range(32)]
```

A pivot exists in every column, so **M is non-singular** and `M⁻¹` drops out of the augmented half. I verified it by round-tripping all 32 basis vectors.

Because the layer XORs whole bytes, the same binary matrix acts independently on each of the 8 bit-planes — one 32×32 inversion covers all of them. No need to think about it bytewise at all.

**Are the round keys known?** Yes, all nine are static in the firmware. Nothing is derived from the input.

Every component is therefore invertible with known parameters, so the whole cipher runs backwards. Reverse the round order and reverse the stage order within each round:

```python
state = target
for r in range(8, 0, -1):
    state = xor(state, rks[r])          # undo key addition
    state = linmul(inv, state)          # undo diffusion
    state = [sinv[b] for b in state]    # undo substitution
plaintext = xor(state, rks[0])          # undo whitening
```

Result:

```
83efaaac9b9a46fbfe0cb665e082127080782320d51c1d134f5bcd157abaf50f
```

The "vow" is raw binary, not a passphrase — which is why brute force or wordlist approaches were never going to land, and why the flag had to be XOR-derived from it rather than compared against it.

Re-encrypting confirms the inversion before doing anything else:

```python
assert encrypt(plaintext) == target     # True
```

And the flag:

```python
flag = bytes(flagmask[i] ^ plaintext[i] for i in range(26))
# b'HTB{c1nd3r_3ng1n3_unw0und}'
```

26 bytes of arbitrary XOR output landing on clean printable ASCII in exactly the right format is a proof in itself — a wrong plaintext would produce noise.

---

## Verification

Two independent confirmations, because a self-consistent solve can still be a self-consistent *mistake*.

**1. Emulator.** I implemented the VM in Python from the opcode table (`emu.py`) and fed it the recovered bytes:

```
$ python3 emu.py < vow.bin
HTB{c1nd3r_3ng1n3_unw0und}
$ python3 -c "import sys; sys.stdout.buffer.write(b'A'*32)" | python3 emu.py
                                    (no output — correct rejection)
```

**2. The real binary under QEMU.** This is the one that actually matters, since it validates my reading of the *interpreter* and not just my reading of the firmware:

```
$ apt-get install -y qemu-user-static libc6-arm64-cross
$ qemu-aarch64-static -L /usr/aarch64-linux-gnu ./cinder < vow.bin
HTB{c1nd3r_3ng1n3_unw0und}
```

---

## Flag

```
HTB{c1nd3r_3ng1n3_unw0und}
```

---

## Notes and takeaways

**The layered design is the point.** Each phase gates the next: you can't read the firmware without the opcode map, can't identify the cipher without the disassembly, and can't produce the flag without actually inverting the cipher. There's no shortcut where solving one layer hands you the answer.

**The scattered opcode encoding is cheap but effective.** Sparse, non-sequential opcode values force you to derive semantics from handler behaviour rather than pattern-matching a conventional ISA. Combined with the opcode sitting in the high byte of a little-endian word, casual hex inspection of the firmware yields nothing.

**Unrolled code looks harder than it is.** ~1000 instructions of `LDB`/`XOR` is visually daunting, but the moment you recognise it as a matrix written longhand, it collapses to a 32-bit integer per row. Recognising algebraic structure beat reading the listing by a wide margin — and parsing the decoded instruction stream to extract it removed all transcription risk.

**XOR-derived output is a strong anti-patch measure.** Because the flag is `mask ⊕ correct_input` and never exists in the binary, the usual "NOP the comparison" reflex produces garbage. Worth remembering both when solving and when writing challenges.

**A faithful emulator is worth the twenty minutes.** It's the difference between "my algebra is self-consistent" and "the machine agrees with me," and it catches subtle modelling errors — the `neg`/`ror` rotate idiom and the shift-amount masking being the likely candidates here.

---

## Appendix — tooling

| File | Purpose |
|---|---|
| `vmdis.py` | VM disassembler for the firmware |
| `extract.py` | Pulls S-box, round keys, target, mask; parses and inverts the GF(2) matrix |
| `solve.py` | Runs the SPN backwards, recovers the input, derives the flag |
| `emu.py` | Standalone VM emulator for verification |
| `vow.bin` | The 32-byte solution input |

Reproduce with:

```
$ python3 solve.py
$ qemu-aarch64-static -L /usr/aarch64-linux-gnu ./cinder < vow.bin
```
