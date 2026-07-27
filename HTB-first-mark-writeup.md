# First Mark — Writeup

**Category:** Reversing
**Flag:** `HTB{cut_f0r_th3_P1NT}`
**Given:** `firstmark.zip` → `first-mark.elf` (a stripped 32-bit RISC-V binary)

The challenge hands you a stripped RISC-V ELF built for a custom emulator. Four of its
instructions are deliberately undocumented "runes." A note recovered "in Veylen's own
hand" fully specifies the third rune; you have to infer the other three from context and
reverse the whole thing to recover the 16-byte secret the binary checks. There is no
input to bruteforce — the mark has to be *derived*.

---

## 1. Recon

```
$ unzip firstmark.zip
$ file first-mark.elf
first-mark.elf: ELF 32-bit LSB executable, UCB RISC-V, soft-float ABI,
                version 1 (SYSV), statically linked, stripped
```

32-bit RISC-V, statically linked, stripped, and *tiny*. Inspecting the sections:

| Section   | VAddr        | Size   |
|-----------|--------------|--------|
| `.text`   | `0x20000000` | `0x178`|
| `.rodata` | `0x20000178` | `0x0bc`|
| `.bss`    | `0x80000000` | `0x010`|

The `.riscv.attributes` string is `rv32i2p1_m2p0_zmmul1p0` — base integer + multiply, no
compressed instructions, no floating point. Entry is `0x20000000` and (as we'll see)
there's an MMIO console at `0x10000000`, so this runs on a bespoke emulator, not Linux.

### Tooling

The system `objdump` doesn't know this architecture (`architecture: UNKNOWN!`), so I used
Capstone, which has a RISC-V backend:

```bash
pip install capstone pyelftools --break-system-packages
```

---

## 2. Disassembly — spotting the four runes

Disassembling `.text` with Capstone, four 32-bit words refuse to decode. Feeding the raw
bytes through as `.word` directives makes them stand out immediately:

```asm
; ---- verify(secret) @ 0x200000d0 ----
200000ec  mv    s0, a0          ; s0 = secret pointer
200000f0  mv    s1, zero        ; s1 = i = 0
200000f4  addi  a2, zero, 0xa5  ; a2 = state = 0xA5   <-- matches the note
200000f8  ...   s2 = 0x200001f4 ; TABLE1
20000100  ...   s3 = 0x20000204 ; TABLE2
20000108  ...   s4 = 0x20000214 ; TABLE3 (targets)

; ---- per-byte loop ----
20000110  add   t0, s0, s1
20000114  lbu   a0, 0(t0)       ; a0 = secret[i]
20000118  add   t0, s2, s1
2000011c  lbu   a1, 0(t0)       ; a1 = TABLE1[i]
20000120  andi  a1, a1, 7       ; a1 &= 7            <-- 3-bit operand => rotate amount
20000124  .word 0x00b5050b      ; RUNE1  rd=a0 rs1=a0 rs2=a1     (custom-0, funct3=0)
20000128  add   t0, s3, s1
2000012c  lbu   a1, 0(t0)       ; a1 = TABLE2[i]
20000130  .word 0x00b5150b      ; RUNE2  rd=a0 rs1=a0 rs2=a1     (custom-0, funct3=1)
20000134  .word 0x00c5052b      ; RUNE3  rd=a0 rs1=a0 rs2=a2     (custom-1, funct7=0)
20000138  mv    a2, a0          ; state = rune3 output           <-- matches the note
2000013c  add   t0, s4, s1
20000140  lbu   a3, 0(t0)       ; a3 = TABLE3[i]
20000144  .word 0x02d5002b      ; RUNE4  rd=zero rs1=a0 rs2=a3   (custom-1, funct7=1)
20000148  addi  s1, s1, 1       ; i++
2000014c  addi  t0, zero, 0x10
20000150  blt   s1, t0, -0x40   ; loop while i < 16
```

Decoding the R-type fields of the four unknown words:

| Rune | Word         | opcode        | funct7 | funct3 | rd   | rs1 | rs2 |
|------|--------------|---------------|--------|--------|------|-----|-----|
| 1    | `0x00b5050b` | `0x0b` custom-0 | 0    | 0      | a0   | a0  | a1  |
| 2    | `0x00b5150b` | `0x0b` custom-0 | 0    | 1      | a0   | a0  | a1  |
| 3    | `0x00c5052b` | `0x2b` custom-1 | 0    | 0      | a0   | a0  | a2  |
| 4    | `0x02d5002b` | `0x2b` custom-1 | 1    | 0      | zero | a0  | a3  |

So the runes come in two pairs that "keep company" by sharing an opcode: custom-0
(runes 1 & 2) and custom-1 (runes 3 & 4).

---

## 3. Program structure

Three routines matter:

- **`puts` @ `0x20000060`** — walks a string, writing each byte to MMIO `0x10000000`
  (with a busy-wait poll), then a newline. Pure output.
- **`main` @ `0x20000094`**:
  ```
  puts("the stone witnesses. it does not bargain. read the four marks or be cast out.")
  verify(0x80000000)        ; buffer in .bss
  puts("ACCEPTED: The First Mark was cut in steel.")
  ```
- **`verify` @ `0x200000d0`** — the 16-round loop above.

### The key realization

`verify` is handed `0x80000000`, which lives in `.bss` — zero-initialised and **never
written to**. There is no `getchar`/`gets` anywhere; `puts` only ever *writes*. So the
program reads no input at all.

That reframes the whole challenge. It isn't "run it and type the flag." It's a **static
recovery**: find the 16 bytes `secret[0..15]` such that every round's RUNE4 assertion
passes. Those bytes *are* the flag. This is exactly the lore — the stone never hands the
mark over; you have to reconstruct it. ("If you want the stone to attest, don't go
looking for the manual Veylen never wrote.")

---

## 4. The data (`.rodata`)

Pulling the three tables and the target out of `.rodata` by address:

```
TABLE1 @0x200001f4 : 03 07 01 05 02 06 04 00  03 07 01 05 02 06 04 00
TABLE2 @0x20000204 : 03 02 03 02 05 07 02 03  05 07 02 03 05 07 02 03
TABLE3 @0x20000214 : 11 7a 35 90 7e 88 b0 59  79 7f 56 6a 3a 10 e9 05   (targets)
```

Two things jump out:

- **TABLE1** is a permutation of `0..7` (repeated) — consistent with rotate amounts,
  reinforced by the `andi a1, a1, 7` right before RUNE1.
- **TABLE2** contains only `{2, 3, 5, 7}` — the **first four primes**. Hold that thought.

---

## 5. Deducing the runes

### RUNE3 — the one with a key

The note is explicit:

> *out = a0 ^ state ^ carry, then updates the hidden carry as carry = old_a0 & state. The
> carry starts at 0, and the state starts at 0xA5 and becomes the rune's output each round.*

So RUNE3 is a stateful, XOR-with-carry-feedback operation:

```
out   = a ^ state ^ carry
carry = a & state          # uses the *incoming* a and the *current* state
state = out                # feedback for the next round
```

`state = 0xA5`, `carry = 0` at the start. The `mv a2, a0` right after RUNE3 in the
disassembly is literally "state becomes the output." Because RUNE4 asserts the output
equals `TABLE3[i]`, we know each round's RUNE3 output — which lets us roll the state and
carry forward deterministically and solve for the value `v` that entered RUNE3:

```
v = out ^ state ^ carry        # out = TABLE3[i]
```

### RUNE1 — rotate

Operand masked to 3 bits (`andi a1,a1,7`), amounts drawn from a `0..7` permutation:
this is a byte **rotate**. Direction (left vs right) is unknown yet — one bit to pin down.

### RUNE2 — the trap I fell into first

My first instinct was that RUNE2 (funct3=1, arbitrary byte operand) was a simple
`xor` / `add` / `sub`. I inverted RUNE3, then tried every combination of
`{rol, ror}` × `{xor, add, sub, rsub}`… and got **zero** printable candidates. Not even
close. That's a strong signal the operation is wrong, not the wiring.

The tell was TABLE2 = `{2, 3, 5, 7}`. Small odd-ish constants used as *multipliers* in a
reversible byte cipher scream **GF(2⁸) multiplication** — the AES `MixColumns` trick.
In a field, every nonzero element is invertible, so multiplying a byte by 2, 3, 5, or 7 is
perfectly reversible (unlike ordinary `× 2 mod 256`, which loses the top bit). RUNE2 being
the "multiply" partner of RUNE1's "rotate" also fits two related custom-0 ops.

So: **RUNE2 = GF(2⁸) multiply** by `TABLE2[i]`, reduced by some field polynomial.

### RUNE4 — the verdict

`rd = zero`, comparing `a0` (RUNE3 output) against `TABLE3[i]`. It's the assertion —
"true, or nothing at all." We don't need its exact trap behaviour; we only need that it
constrains each round's output to `TABLE3[i]`.

---

## 6. Inverting the pipeline

Forward, each byte goes:

```
secret[i] --RUNE1--> ror/rol by (TABLE1[i]&7)
          --RUNE2--> GF(2^8) multiply by TABLE2[i]
          --RUNE3--> ^ state ^ carry   (== TABLE3[i], enforced by RUNE4)
```

To invert, walk it backwards per round:

```
v = TABLE3[i] ^ state ^ carry          # undo RUNE3
u = gfmul(v, gfinv(TABLE2[i]))         # undo RUNE2 (multiply by field inverse)
secret[i] = rotate_back(u, TABLE1[i]&7)# undo RUNE1
# then advance RUNE3 state:  carry = v & state ;  state = TABLE3[i]
```

Two unknowns remain: rotate direction and the field polynomial. Every operation is
invertible, so the correct pair yields a *unique*, fully-printable 16 bytes. I brute-forced
`{rol, ror}` against the standard degree-8 irreducible polynomials. Exactly one combination
produced clean ASCII:

```
poly = 0x11b   direction = ror   ->   cut_f0r_th3_P1NT
```

`0x11b` is the AES/Rijndael polynomial, and `ror` is the rotate direction. Everything lines
up with the AES-flavoured hint from TABLE2.

---

## 7. Verification

Re-running the pipeline **forward** on the recovered bytes reproduces the target exactly —
i.e. the stone attests:

```
candidate : cut_f0r_th3_P1NT
forward   : 11 7a 35 90 7e 88 b0 59 79 7f 56 6a 3a 10 e9 05
target    : 11 7a 35 90 7e 88 b0 59 79 7f 56 6a 3a 10 e9 05   ✓ MATCH
```

## Flag

```
HTB{cut_f0r_th3_P1NT}
```

---

## Appendix A — final rune definitions

| Rune | Encoding                          | Operation |
|------|-----------------------------------|-----------|
| 1    | custom-0, funct3=0                | `ror(byte, TABLE1[i] & 7)` |
| 2    | custom-0, funct3=1                | `gfmul(byte, TABLE2[i])` in GF(2⁸), poly `0x11b` |
| 3    | custom-1, funct3=0, funct7=0      | `out=a^state^carry; carry=a&state; state=out` (state0=`0xA5`, carry0=0) |
| 4    | custom-1, funct3=0, funct7=1      | `assert(a == TABLE3[i])` |

## Appendix B — self-contained solver

```python
#!/usr/bin/env python3
M = 0xFF
POLY = 0x11B  # AES/Rijndael field polynomial

TABLE1 = [0x3,0x7,0x1,0x5,0x2,0x6,0x4,0x0, 0x3,0x7,0x1,0x5,0x2,0x6,0x4,0x0]
TABLE2 = [0x3,0x2,0x3,0x2,0x5,0x7,0x2,0x3, 0x5,0x7,0x2,0x3,0x5,0x7,0x2,0x3]
TARGET = [0x11,0x7a,0x35,0x90,0x7e,0x88,0xb0,0x59,
          0x79,0x7f,0x56,0x6a,0x3a,0x10,0xe9,0x05]

def ror(x,n):
    x&=M; n&=7
    return ((x>>n)|(x<<((8-n)&7)))&M if n else x
def rol(x,n):
    x&=M; n&=7
    return ((x<<n)|(x>>((8-n)&7)))&M if n else x
def gfmul(a,b,poly=POLY):
    r=0
    for _ in range(8):
        if b&1: r^=a
        b>>=1; hi=a&0x80; a=(a<<1)&M
        if hi: a^=poly&M
    return r&M
def gfinv(k,poly=POLY):
    return next(x for x in range(256) if gfmul(k,x,poly)==1)

def recover():
    inv={k:gfinv(k) for k in set(TABLE2)}
    state,carry=0xA5,0; flag=bytearray()
    for i in range(16):
        out=TARGET[i]
        v=out^state^carry                 # undo RUNE3
        u=gfmul(v,inv[TABLE2[i]])         # undo RUNE2
        flag.append(rol(u,TABLE1[i]&7))   # undo RUNE1
        carry=(v&state)&M; state=out      # advance RUNE3 state
    return bytes(flag)

def forward(inp):
    state,carry,outs=0xA5,0,[]
    for i in range(16):
        x=ror(inp[i],TABLE1[i]&7)
        x=gfmul(x,TABLE2[i])
        out=x^state^carry
        carry=(x&state)&M; state=out; outs.append(out)
    return outs

mark=recover()
assert forward(list(mark))==TARGET
print("HTB{%s}" % mark.decode())
```

## Appendix C — lore ↔ mechanics

The description isn't just flavour; every line maps to a mechanic:

- *"four of its instructions undocumented on purpose"* → the four custom opcodes Capstone can't decode.
- *"Common chisels read most of it and stall exactly there"* → a stock disassembler decodes everything but those four words.
- *"Learn what those four runes do from the company they keep"* → infer each rune from its operands/tables (`&7` ⇒ rotate; primes ⇒ GF multiply).
- *"cut in steel" / "keep your steel"* → the `.rodata` strings; the mark itself is `cut_f0r_th3_...`.
- The stone reading no input and only answering "true, or nothing" → `verify` on a zero buffer with assert-only RUNE4; the mark must be reconstructed, never handed over.
