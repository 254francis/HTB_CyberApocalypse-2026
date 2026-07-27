# Fractured Seal — HTB (crypto)

> *One of the Registry's oldest key-scrolls survived the fall of Crownspire, though time and fire spared only fragments of its writing, and most in the vault dismissed it as useless. Caldrin didn't. She always said a seal doesn't have to be whole to still remember the door it once opened.*

**Flag:** `HTB{r3c0v3r1ng_RSA_k3ys___l1k3___Me0w___me0o00o0o0w___Me0w}`

**Category:** Crypto — RSA partial key recovery / Coppersmith
**TL;DR:** The redacted PEM preserves character positions, so base64 offsets map directly onto DER offsets. `n` survives intact except for its last byte, and a surviving fragment in the middle of the file turns out to be the *start* of `prime2` — the top 576 bits of `q`. That is more than the 512 bits Coppersmith needs, so lattice reduction recovers the remaining 448 bits and the key falls out.

---

## 1. Files

```
crypto_fractured_seal/
├── encrypt.py
├── flag.enc            # 256 bytes
└── fractured_seal.pem  # PEM with most characters replaced by '*'
```

`encrypt.py` is textbook, no padding:

```python
p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 0x10001
d = pow(e, -1, (p-1)*(q-1))

m = bytes_to_long(open('flag.txt', 'rb').read())

open('seal.pem', 'wb').write(RSA.construct((n, e, d)).export_key())
open('flag.enc', 'wb').write(long_to_bytes(pow(m, e, n)))
```

So the whole challenge is: reconstruct enough of the exported private key to factor `n`.

## 2. Reading the damage

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAjK59ahXlX7a+oF+jt5icukpGeNXXgQO4D3jPeLaGAupJm6a6      <- line 0
9PnWCf0W3QDhmCPxLYWSr1C4DvxP23UlvP8Lcfu+w/oIS0jDHkfnv+m1Qku/ii9w
ehy/iRNuUeaH88K4AA0XFvJoak5I0Igi5ksP/CsyGMRJbUe898eLZjYOYAoA2+fi
Ljjfg...
iMFz5uhwcU5njXnHdZRfrCTaUWBLLxmE8PCbIuy8hJqhL+iD1OcwTS8Yo8xoTtoc      <- line 4
7HFFfXYNoKjnqgp+LOmLwQGQeO2Yo1Hb8SCVd***************************      <- line 5
****************************************************************      <- lines 6..12
****************************************************2msCgYEAwLGx      <- line 13
cJ7/YCgq9GPDS16cHPNZEmYrbSX+atzUBBO2jLYg0QbXfitTIHfU+55DqIxFQOcu      <- line 14
+CahrPQQROoZAAIPg0LdaGd+3R3/ri**********************************      <- line 15
...
*****************************   ／l、
***************************   （ﾟ､ ｡ ７
****************************   l、 ~ヽ
****************************   じしf_, )ノ
-----END RSA PRIVATE KEY-----
```

The single most important observation: **the redaction is positional**. Every line is still exactly 64 characters, and each `*` stands for exactly one lost base64 character. That means a visible run of base64 starting at an index divisible by 4 can be decoded in isolation and lands at a *known* byte offset in the DER.

The ASCII cat is a troll — it wrecks line lengths, but only in the region that is already fully redacted, so it costs nothing.

## 3. Mapping the DER

`RSAPrivateKey` is a `SEQUENCE` of nine `INTEGER`s in a fixed order:

```
version, n, e, d, p, q, dP, dQ, qInv
```

Decoding the visible head of the file gives:

```
30 82 04 a3      SEQUENCE, 1187 bytes
02 01 00         version = 0
02 82 01 01 00   INTEGER, 257 bytes -> n (2048-bit, leading 0x00)
```

Which fixes the byte layout for a 2048-bit key:

| field | header | data | bytes |
|---|---|---|---|
| SEQ header | | | 0–3 |
| version | | | 4–6 |
| `n` | 7–10 | 11–267 | 261 |
| `e` | 268–269 | 270–272 | 5 |
| `d` | 273–276 | 277–532 | 260 |
| `p` | 533–535 | 536–664 | 132 |
| **`q`** | **665–668** | **669–796** | **132** |
| `dP`, `dQ`, `qInv` | | 797–1189 | ~131 each |

## 4. Recovering `n` (almost for free)

Lines 0–4 are intact and line 5 contributes 37 visible characters before the first `*`:

```
5 * 64 + 37 = 357 base64 characters
357 // 4 = 89 complete groups -> 267 bytes (offsets 0..266)
```

`n`'s data runs 11–267, so **every byte of `n` is present except the very last one**.

The 357th character (`d`, left over from the incomplete group) is not useless — it still encodes the top 6 bits of byte 267:

```python
top6 = B64.index('d') << 2      # 'd' = 29 = 0b011101  ->  byte267 = 0b011101xx
```

That leaves 4 candidates, and `n = p*q` with both primes odd, so `n` must be odd — 2 candidates. Cheap enough to just try both.

## 5. The surviving fragment is the head of `q`

Line 13 begins at character `13 * 64 = 832`; the visible text starts 52 characters in, at **884**. Since `884 % 4 == 0`, that fragment decodes on its own, at byte offset `884 / 4 * 3 = `**663**.

```python
r2 = body[13][52:] + body[14] + body[15].split('*')[0]
d2 = base64.b64decode(r2[:len(r2)//4*4])
# da 6b | 02 81 81 00 | c0 b1 b1 70 9e ff ...
```

Read that against the offset table:

- `da 6b` — bytes 663–664, the last two bytes of `p` (useless on their own)
- `02 81 81 00` — bytes 665–668, an `INTEGER` header for a 129-byte value, i.e. a 1024-bit prime with a leading zero → this is **`prime2` = `q`**
- everything after — bytes 669 onward, the **most significant** bytes of `q`

This is the part worth pausing on. My first offset estimate was off by one redacted line, which put the fragment 48 bytes *inside* `q` — i.e. middle bits, which is a much harder (bivariate) problem. Recounting the star lines moved it to 663, exactly on `p`'s tail, and the `02 81 81 00` header confirms the alignment is right. If your fragment doesn't land on a plausible DER header, your line count is wrong.

Total usable: 106 visible characters → 25 complete groups → 78 bytes covering 663–740. Subtracting the 6 header bytes:

```
72 bytes of q known = 576 high bits
1024 - 576 = 448 unknown low bits
```

## 6. Coppersmith

Write `q = q_hi + x` where `q_hi` is the known prefix shifted up by 448 bits and `0 <= x < 2^448`.

We want a small root of

```
f(x) = x + q_hi   (mod q),   q | N,   q ≈ N^0.5
```

Coppersmith's method with `beta = 0.5` and degree `d = 1` recovers roots bounded by `N^(beta²/d) = N^0.25 = 2^512`. Our unknown is `2^448` — comfortably inside the bound, with 64 bits of margin. (This is the general rule of thumb: **half the bits of a prime, contiguous, at either end, is enough.**)

No Sage in the box, so a hand-rolled Howgrave-Graham lattice over fpylll:

```python
polys  = [Poly(N**(m-1-i), x) * f**i for i in range(m)]   # n^(m-1-i) · f^i
polys += [Poly(x**j, x) * f**m for j in range(t)]         # x^j · f^m
```

with `m = t = 8`, giving a 16×16 lattice of degree ≤ 15. Columns are scaled by `X^c` (`X = 2^448`) so that short vectors correspond to polynomials that are small at `x = x0`; after `LLL.reduction` the coefficients are unscaled by dividing back out.

For root extraction I skipped numerical root-finding entirely: any two of the short vectors share the factor `(x - x0)`, so a polynomial `gcd` over ℚ of consecutive reduced rows gives a degree-1 polynomial and the root directly.

```
root  = 4945335642762823123276447467829746811666302689290251050495196243031975093471...
q     = 135314408378842790751605878050931209066067635249717498350882274491410611188834...
N % q == 0   ✔
```

The first `n` candidate was the right one.

## 7. Decrypt

With `p` and `q` in hand it's plain textbook RSA — no padding, so `long_to_bytes(pow(c, d, n))` is the flag:

```
HTB{r3c0v3r1ng_RSA_k3ys___l1k3___Me0w___me0o00o0o0w___Me0w}
```

## 8. Full solution

`solve.py` (deps: `pip install fpylll cysignals sympy` — **install `cysignals` first**, `fpylll` imports it at runtime and fails with a bare `ModuleNotFoundError` otherwise):

```python
#!/usr/bin/env python3
import base64
from fpylll import IntegerMatrix, LLL
from sympy import Poly, symbols, gcd, Rational

PEM, ENC = 'fractured_seal.pem', 'flag.enc'
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

body = [l for l in open(PEM).read().split('\n')
        if l and not l.startswith('-----')]

# --- region 1: DER header + all of n but its last byte ---------------
r1 = ''.join(body[0:5]) + body[5].split('*')[0]          # 357 chars
d1 = base64.b64decode(r1[:len(r1)//4*4])                 # bytes 0..266
tail = r1[len(r1)//4*4:]                                 # 1 leftover char
assert d1[:12] == bytes.fromhex('308204a3' '020100' '02820101' '00')

top6 = B64.index(tail) << 2                              # top 6 bits of byte 267
n_cands = [int.from_bytes(d1[11:] + bytes([top6 | lo]), 'big') for lo in range(4)]
n_cands = [n for n in n_cands if n & 1]                  # n is odd

# --- region 2: fragment at char 884 -> byte 663, i.e. head of q ------
start = 13*64 + 52
assert start % 4 == 0
r2 = body[13][52:] + body[14] + body[15].split('*')[0]
d2 = base64.b64decode(r2[:len(r2)//4*4])                 # bytes 663..740
assert d2[2:6] == bytes.fromhex('02818100')              # INTEGER 129 -> prime2

q_known = d2[6:]                                         # 72 bytes = 576 high bits
UNK  = 1024 - len(q_known)*8                             # 448
q_hi = int.from_bytes(q_known, 'big') << UNK
X    = 1 << UNK

# --- Coppersmith: small root of f(x) = x + q_hi mod q, q | N ---------
def coppersmith(N, a, X, m=8, t=8):
    x = symbols('x')
    f = Poly(x + a, x)
    polys  = [Poly(N**(m-1-i), x) * f**i for i in range(m)]
    polys += [Poly(x**j, x) * f**m for j in range(t)]

    dim, deg = len(polys), m + t - 1
    B = IntegerMatrix(dim, deg + 1)
    for r, p in enumerate(polys):
        cs = p.all_coeffs()[::-1]                        # low -> high
        for c in range(deg + 1):
            B[r, c] = (int(cs[c]) if c < len(cs) else 0) * X**c
    LLL.reduction(B)

    def unscale(i):
        cs = [Rational(B[i, c], X**c) for c in range(deg + 1)]
        return Poly(sum(cs[c] * x**c for c in range(deg + 1)), x)

    for i in range(dim - 1):
        g = gcd(unscale(i), unscale(i + 1))
        if g.degree() == 1:
            hi, lo = g.all_coeffs()
            if hi != 0 and (-lo/hi).is_integer:
                return int(-lo/hi)
    return None

for N in n_cands:
    root = coppersmith(N, q_hi, X)
    if root is None:
        continue
    q = q_hi + root
    if N % q:
        continue
    p = N // q
    d = pow(0x10001, -1, (p-1)*(q-1))
    c = int.from_bytes(open(ENC, 'rb').read(), 'big')
    m = pow(c, d, N)
    print(m.to_bytes((m.bit_length()+7)//8, 'big').decode())
    break
else:
    print('no factorisation found')
```

## 9. Takeaways

- **Positional redaction leaks structure.** Any redaction that preserves character count in a base64 blob preserves byte offsets. Compute them before guessing at content.
- **Base64 alignment is the whole game.** A fragment starting at an index `≡ 0 mod 4` decodes cleanly and independently; one that doesn't needs up to 4 candidate prefixes brute-forced. Here it was gift-wrapped at 884.
- **Sanity-check offsets against DER headers.** `02 81 81 00` / `02 82 01 01 00` are unmistakable landmarks. If your computed offset doesn't line up with one, recount your redacted lines rather than pressing on.
- **Half a prime is a whole prime.** 512 contiguous bits of a 1024-bit factor (top *or* bottom) is enough for Coppersmith; here 576 gave a comfortable cushion.
- **Don't discard partial base64 characters.** The single trailing `d` cut the `n` search space from 256 to 4 (then 2, by parity).
- `RSA.construct((n, e, d))` re-derives `p` and `q` and exports all nine CRT parameters — which is exactly why a fragment from the middle of the file was recoverable at all.
