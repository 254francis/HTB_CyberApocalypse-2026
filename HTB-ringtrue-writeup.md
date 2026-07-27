# Ringtrue — Reversing Write-up

**Flag:** `HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}`
**Category:** Reversing
**Binary:** `ringtrue` — ELF 64-bit LSB PIE, x86-64, dynamically linked, **not stripped**
**SHA-256:** `8014ba38b5203ab41d8b442af1f380af38ca57fcae676e8788aba743b17d9129`

---

## 0. TL;DR

The device is a hand-rolled **integer-only int8 MLP (8→8→8→8)**. It accepts eight
integers, runs them through three dense layers with a leaky activation, and compares
the final layer's output against a hard-coded target vector `ECHO_S` with **exact
equality**.

Because every operation is exact integer arithmetic with no requantisation, and the
activation is strictly monotonic on both branches, the network is **trivially
invertible**. Solving three 8×8 linear systems backwards recovers the unique input:

```
83 97 108 116 67 114 119 110   →   ASCII "SaltCrwn"
```

Those eight bytes are then used as an SHA-256 key to decrypt `VOW_CIPHER`, which is the
flag.

---

## 1. Recon

```bash
$ unzip ringtrue.zip
$ file ringtrue
ringtrue: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
          interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

The binary is **not stripped**, which is the "Eastreach was careless and left the device
open to read" hint from the description. `strings` immediately gives away the design:

```
npu: resonance-core init ...
npu: resonance_core.tflm - MLP 8-8-8-8, int8, leaky ... ok
npu: weights symmetric int8 (zp=0), per-tensor scale
adc: tone-sensor ch0..ch7 online (8 samples / attune)
  attune>
%d %d %d %d %d %d %d %d
```

So: read 8 integers with `sscanf`, feed them to a small quantised neural net.

The symbol table hands over the entire model:

```bash
$ readelf -sW ringtrue | grep -Ei "L0_|L1_|L2_|VOW|ECHO|W_SCALE|dense"
  12: 0000000000001309    60 FUNC   LOCAL  dense
  26: 0000000000005050    12 OBJECT GLOBAL W_SCALE
  27: 0000000000005140    64 OBJECT GLOBAL L1_W
  35: 0000000000005020     4 OBJECT GLOBAL VOW_LEN
  40: 0000000000005180    64 OBJECT GLOBAL L0_W
  42: 0000000000005100    64 OBJECT GLOBAL L2_W
  47: 0000000000005030    30 OBJECT GLOBAL VOW_CIPHER
  59: 00000000000050e0    32 OBJECT GLOBAL L0_B
  60: 00000000000050a0    32 OBJECT GLOBAL L2_B
  61: 00000000000050c0    32 OBJECT GLOBAL L1_B
  62: 0000000000005060    64 OBJECT GLOBAL ECHO_S
```

Sizes tell us the types straight away:

| Symbol | Size | Interpretation |
|---|---|---|
| `Ln_W` | 64 B | 8×8 matrix of `int8` |
| `Ln_B` | 32 B | 8 × `int32` bias |
| `ECHO_S` | 64 B | 8 × `int64` target |
| `W_SCALE` | 12 B | 3 × `float` (dequant scales) |
| `VOW_CIPHER` | 30 B | ciphertext, length in `VOW_LEN` |

---

## 2. Reversing `dense()`

The whole inference kernel is 60 bytes:

```asm
0000000000001309 <dense>:
  1309:  mov    r11d, 0x0                          ; j = 0
  130f:  movsxd r9, DWORD PTR [rsi+r11*4]          ; acc = (int32)bias[j]
  1313:  mov    r10, rdi                           ; row = W + j*8
  1316:  mov    eax, 0x0                           ; i = 0
  131b:  movsx  r8, BYTE PTR [r10+rax*1]           ; (int8)row[i]
  1320:  imul   r8, QWORD PTR [rdx+rax*8]          ; * (int64)in[i]
  1325:  add    r9, r8                             ; acc += ...
  1328:  add    rax, 0x1
  132c:  cmp    rax, 0x8
  1330:  jne    131b
  1332:  mov    QWORD PTR [rcx+r11*8], r9          ; out[j] = acc
  1336:  add    r11, 0x1
  133a:  add    rdi, 0x8                           ; next row (row-major)
  133e:  cmp    r11, 0x8
  1342:  jne    130f
  1344:  ret
```

In C:

```c
// dense(int8_t *W, int32_t *B, int64_t *in, int64_t *out)
for (int j = 0; j < 8; j++) {
    int64_t acc = B[j];
    for (int i = 0; i < 8; i++)
        acc += (int8_t)W[j*8 + i] * in[i];
    out[j] = acc;
}
```

**The key observation: there is no requantisation.** A real TFLite int8 kernel would
multiply by a fixed-point scale and clamp back into `[-128, 127]` after every layer.
This one keeps the full `int64` accumulator. `W_SCALE = {0.015625, 0.00781, 0.011719}`
is present but never touched by the maths — it's only there to make the model look
plausible (and, together with the boot log, to bait you into a brute-force mindset).

That single omission is what makes the challenge solvable, because the forward pass is
now **exact integer linear algebra** rather than a lossy quantised map.

---

## 3. Reversing the activation

Between layers, `main` runs this over the 8 accumulators:

```asm
  1acb:  mov    rax, QWORD PTR [rsp+rdx*1+0x70]
  1ad0:  lea    rcx, [rax+rax*1]        ; rcx = 2*x
  1ad4:  test   rax, rax
  1ad7:  cmovs  rax, rcx                ; if (x < 0) x = 2*x
  1adb:  mov    QWORD PTR [rsp+rdx*1+0xb0], rax
```

i.e.

```c
y = (x < 0) ? 2*x : x;
```

A "leaky ReLU" with a **negative slope of 2** rather than the usual 0.01 — which makes
sense in an integer kernel, since a fractional slope would need a division. It is
piecewise linear, strictly increasing, and therefore bijective over ℤ. Its inverse is:

```c
x = (y < 0) ? y/2 : y;      // y must be even when negative
```

The evenness requirement is a free consistency check on the solve.

---

## 4. The check

```asm
  1aa6:  lea    rcx, [rsp+0x70]
  1ab3:  lea    rsi, [rip+...]      # L0_B
  1aba:  lea    rdi, [rip+...]      # L0_W
  1ac1:  call   dense               ; z0 = L0_W·x + L0_B
         ... leaky ...              ; a0
  1b01:  lea    rdi, [rip+...]      # L1_W
  1b08:  call   dense               ; z1 = L1_W·a0 + L1_B
         ... leaky ...              ; a1
  1b48:  lea    rdi, [rip+...]      # L2_W
  1b4f:  call   dense               ; z2 = L2_W·a1 + L2_B

  1b59:  mov    ebx, 0x1            ; ok = 1
  1b6a:  mov    rsi, QWORD PTR [rcx+rax*1]      ; ECHO_S[k]
  1b6e:  cmp    QWORD PTR [rsp+rax*1+0x30], rsi
  1b73:  cmovne ebx, edx            ; ok = 0 on any mismatch
  1b7e:  jne    1b6a
  1b86:  test   ebx, ebx
  1b88:  jne    1740               ; failure path (redraw console)
```

Note there is **no activation after layer 2**. So the win condition is exactly:

```
L2·f(L1·f(L0·x + b0) + b1) + b2 == ECHO_S
```

where `f` is the leaky activation. The description's "eight of them, each can be any
value, and far too many to try one by one" is honest — the input space is unbounded
`int` (parsed with `%d`). But we never need to search it.

---

## 5. Extracting the model

Everything lives in `.data` at vaddr `0x5000`, which for this binary maps 1:1 to file
offset `0x5000`, so a flat read of the file is enough — no need to load it.

```
L0_W = [[  5,  13,  10,  14,   1,   0, -15,  12],
        [  4,   4,   3,   1,  11,  -3, -10,  -1],
        [ 10,   3,   1, -11, -12,   5,  12,  14],
        [ 10,   2,   3,   7,   7,  -6,  -1,  -4],
        [ 16,  10, -10,  12,   5,   6,   2,  -5],
        [ 15,  -1,  -7,  -3,   9,   7,   1,  -5],
        [  6, -12,  -8, -10,   0,   7, -15,  15],
        [  4,  -9,  -4,  12,  -4,  16,  15,   5]]

L1_W = [[ 14,  -1,  13,  -3, -15,  10,   1, -14],
        [ 16,  16,  12,  -7,  14,   5,  -8,  -7],
        [ -2,   3,   7,  15, -12,  11,   1,  12],
        [ -9,  -8, -14,  -2,  -3,   3,  -1,   0],
        [-11, -13,   6,   7,  -3,  -4,   0,  16],
        [ -4,   2,  -4,  11,  16, -10,   5,  -5],
        [ -8,  -4,   1,   8,   3, -14, -12,   6],
        [-13, -12,   5,  13,  14, -15,  15,   5]]

L2_W = [[  9, -15,   0, -16,   2, -15,   6,  -6],
        [  8,   0,  -5,  -4,  -1,  10,  -7,   3],
        [ -9, -15, -14,  -7,  -5,  -4, -11,   9],
        [  9,  -9,  15,  13,   1,  -8,   1,  -3],
        [-13,   9,  -8,   4, -16,  11,  11,  12],
        [-10, -12,  -1, -10,  -1,  11,   6,  -4],
        [  6,  -4,  -5, -13,  -3,   8,   6,  -4],
        [ -2, -12, -15,   4,  16,  -9,  13, -13]]

L0_B = [ 541, -548, 1968, 1610,   68, -1078,  -42, -2020]
L1_B = [-1709,  704, 1565,  304, -209,  1690, -1151,  245]
L2_B = [ 506,  -234, 1551, 1479, 1058,  1130,  1320,  330]

ECHO_S = [1542223, 574187, -2694563, -3518303,
           383776, 576877,  2637871, -2518822]
```

---

## 6. Inverting the network

Three steps, repeated per layer, walking from the output back to the input:

1. **Undo the dense layer.** Solve `Ln_W · v = target − Ln_B` exactly over ℚ
   (Gauss-Jordan with `fractions.Fraction` — no floats, no rounding, and no need for
   z3 or an ILP solver). All three matrices turn out to be non-singular, so each step
   has a **unique** solution.
2. **Check integrality.** Every recovered vector must be integral. It is.
3. **Undo the activation.** `x = y/2` if `y < 0`, else `y`. Every negative value must be
   even. It is.

Working backwards:

```
a1 (input to L2) = [ 25473, 162408,  49600, -226556,  33555,  20062, 68975,  9391]
z1               = [ 25473, 162408,  49600, -113278,  33555,  20062, 68975,  9391]
a0 (input to L1) = [  4523,   -586,   4655,    2996,   3385,   -128, -4138,  2290]
z0               = [  4523,   -293,   4655,    2996,   3385,    -64, -2069,  2290]
x                = [    83,     97,    108,     116,     67,    114,   119,   110]
```

And `[83, 97, 108, 116, 67, 114, 119, 110]` is ASCII for **`SaltCrwn`** — "Salt Crown",
which fits House Eastreach's brine/salt theming and confirms the solve is the intended
one rather than an unintended collision.

### Solver

```python
#!/usr/bin/env python3
import struct
from fractions import Fraction

data = open('ringtrue', 'rb').read()          # .data vaddr == file offset

def i8s(v):  return [x - 256 if x > 127 else x for x in data[v:v+64]]
def i32s(v): return list(struct.unpack('<8i', data[v:v+32]))
def i64s(v): return list(struct.unpack('<8q', data[v:v+64]))
def mat(w):  return [w[j*8:j*8+8] for j in range(8)]

M0, M1, M2 = mat(i8s(0x5180)), mat(i8s(0x5140)), mat(i8s(0x5100))
B0, B1, B2 = i32s(0x50e0), i32s(0x50c0), i32s(0x50a0)
ECHO       = i64s(0x5060)

def solve(M, b, target):
    """Exact rational solve of M*x + b = target."""
    n = 8
    A = [[Fraction(M[j][i]) for i in range(n)] + [Fraction(target[j] - b[j])]
         for j in range(n)]
    for c in range(n):
        p = next(r for r in range(c, n) if A[r][c] != 0)   # non-singular
        A[c], A[p] = A[p], A[c]
        pv = A[c][c]
        A[c] = [v / pv for v in A[c]]
        for r in range(n):
            if r != c and A[r][c] != 0:
                f = A[r][c]
                A[r] = [A[r][k] - f * A[c][k] for k in range(n + 1)]
    out = [A[i][n] for i in range(n)]
    assert all(v.denominator == 1 for v in out), "non-integral solution"
    return [int(v) for v in out]

def inv_leaky(y):
    """Inverse of  out = (x < 0) ? 2*x : x"""
    r = []
    for v in y:
        if v >= 0:
            r.append(v)
        else:
            assert v % 2 == 0, f"odd negative value {v}"
            r.append(v // 2)
    return r

a1 = solve(M2, B2, ECHO)
a0 = solve(M1, B1, inv_leaky(a1))
x  = solve(M0, B0, inv_leaky(a0))

print("tones :", ' '.join(map(str, x)))
print("ascii :", bytes(x).decode())
```

```
$ python3 solve.py
tones : 83 97 108 116 67 114 119 110
ascii : SaltCrwn
```

---

## 7. Triggering the win

```bash
$ echo "83 97 108 116 67 114 119 110" | ./ringtrue
```

```
  ECHO OF ASTRAEL   your tone (#)   vs   the echo (.)
  HARMONICS  h0 #### h1 #### h2 #### h3 ####
             h4 #### h5 #### h6 #### h7 ####
  RESONANCE [##############################] 100%

        \  |  /
      -- ***** --      IT RINGS TRUE
        /  |  \        The First Mark is yours.

  vault-seal: OPEN

  +-- ash-vault - sealed vow ---------------------------------+
  |  HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}                           |
  +-----------------------------------------------------------+
```

---

## 8. Bonus: decrypting the vow offline

The flag isn't stored in plaintext. On the success path, `main` derives a keystream from
the tones with an inlined SHA-256 (recognisable by the IV constants `0x6a09e667`,
`0xbb67ae85`, …, at `0x1d2d`, the `K` table at `0x3a80`, and the `rol/ror/shr`
schedule at `0x1ce5`):

```asm
  1bb7:  mov  edx, DWORD PTR [rsp+rax*4+0x10]
  1bbb:  mov  BYTE PTR [rsp+rax*1+0x1f4], dl   ; low byte of each tone -> key[8]
  ...
  1bfa:  mov  ecx, 0x20
  1c00:  idiv ecx                              ; counter = offset / 32
  1c02..1c22: store counter as 4 LE bytes at key[8..11]
  1c5e:  mov  BYTE PTR [rsp+0x26c], 0x80       ; SHA-256 padding
  1c66:  mov  BYTE PTR [rsp+0x29f], 0x60       ; length = 0x60 bits = 12 bytes
  ...
  1ee0:  movzx edx, BYTE PTR [rsi+rax]         ; VOW_CIPHER[off+i]
  1ee4:  xor   dl, BYTE PTR [rax+rcx]          ; ^ keystream[i]
```

So it is CTR-mode-style keystream generation:

```
keystream_block(n) = SHA256( tone_bytes[8] || le32(n) )
plaintext[i]       = VOW_CIPHER[i] ^ keystream_block(i / 32)[i % 32]
```

Only the **low byte** of each tone is used, which is why `SaltCrwn` is the meaningful
form of the key — and why the model was built so that the unique preimage lands in
printable ASCII.

```python
import hashlib, struct

data    = open('ringtrue', 'rb').read()
VOW_LEN = struct.unpack('<i', data[0x5020:0x5024])[0]      # 30
CIPHER  = data[0x5030:0x5030 + VOW_LEN]

key = bytes(t & 0xff for t in [83, 97, 108, 116, 67, 114, 119, 110])

out = bytearray()
for off in range(0, VOW_LEN, 32):
    ks = hashlib.sha256(key + struct.pack('<I', off // 32)).digest()
    for i in range(min(32, VOW_LEN - off)):
        out.append(CIPHER[off + i] ^ ks[i])

print(out.decode())
```

```
$ python3 decrypt.py
HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}
```

---

## 9. Takeaways

- **Any ML-flavoured crackme is only as strong as its non-linearities.** With a
  monotonic piecewise-linear activation and invertible weight matrices, an "AI lock" is
  just a stack of linear systems.
- **The missing requantisation is the whole bug.** With real per-layer scaling and
  clamping to `int8`, the map would be many-to-one and lossy, and this clean backwards
  solve would fail — you'd be pushed toward z3 / an ILP over a bounded domain instead.
- **Do the arithmetic exactly.** Floating-point Gaussian elimination would have produced
  values like `82.99999999997`, and the `int64` equality check is unforgiving. `Fraction`
  makes the integrality of every intermediate a free correctness proof.
- **`W_SCALE`, the TFLM boot log, and "far too many to try one by one" are all
  misdirection** — flavour designed to sell the model as a genuine quantised network and
  push you toward brute force.

## Files

- `solve.py` — recovers the tones by inverting the network
- `decrypt.py` — decrypts `VOW_CIPHER` offline, no binary execution needed
