# The Ashen Field — HTB Crypto Writeup

**Category:** Cryptography (Multivariate / HFE)
**Flag:** `HTB{e1th3r_gr0bn3r_0r_v4r13ty___1t_st1ll_w0rks!th4nks_f4l4y_f0r_y0ur_4tt4ck_0n_HFE}`

> *Deep beneath the Ash-Vault rests a relic the Cinderbound once swore could preserve truth without ever revealing it, a public rite built from equations, guarded only by the silent calculations its keepers left behind before they vanished.*

"A public rite built from equations" = a multivariate public-key cryptosystem. The flavour here is **HFE (Hidden Field Equations)**, and the implementation contains two independent bugs that reduce the whole thing to a linear system over GF(2).

---

## 1. Files

```
crypto_ashen_field/
├── source.sage    # keygen + encryption
└── output.txt     # public key (137 polynomials), encrypted key, AES-ECB flag
```

`output.txt` is ~152 KB, three lines:

| Line | Content |
|---|---|
| 1 | `str(PK)` — a Sage vector of 137 multivariate polynomials in `x1..x137` |
| 2 | `encrypted_key` — a list of 137 bits |
| 3 | `enc_flag` — hex, AES-128-ECB ciphertext of the flag |

---

## 2. Reading the source

### 2.1 The trapdoor construction

```python
q = 2
N = 137

def keygen(n):
    K = GF(q)
    R = PolynomialRing(K, [f"x{i}" for i in range(1, n+1)], n)
    J = ideal([x^q - x for x in R.gens()])
    H = R.quotient_ring(J, _vars)          # <-- built, then never used

    S_B = random_vector(K, n)
    T_B = random_vector(K, n)
    while True:
        S_A, T_A = [matrix.random(K, n, n) for _ in range(2)]
        if not False in [S_A.is_singular(), T_A.is_singular()]:
            break

    Rv = vector(R, n, R.gens())
    Rv = S[0] * Rv + S[1]                  # affine forms in x1..xn

    PRK.<x> = PolynomialRing(K)
    PRL.<t> = PolynomialRing(R)
    g = PRK.irreducible_element(n)         # degree-137 irreducible over GF(2)
    Q  = PRL.quotient_ring(PRL.ideal([g])) # ~ GF(2^137), coefficients in R

    F = PRL(Rv.list()[::-1])
    F = Q(F^(2*q) + F^q + 1)               # <-- the "hidden" central map

    PK = vector(R, n, F.list()[::-1])
    PK = T[0] * PK + T[1]
    return PK
```

This is the textbook HFE shape: **public key = T ∘ F ∘ S**, where

- `S` and `T` are secret **affine** maps over GF(2)^137 (the "silent calculations its keepers left behind"),
- `F` is the **central map**, computed in the big field `L = GF(2)[t]/(g) ≅ GF(2^137)`.

The 137 coordinates of the input vector are packed into a single element of `L`, pushed through `F`, then unpacked back into 137 coordinates.

### 2.2 Encryption

```python
def encrypt(P, PK):
    l = len(P.bits())
    msg = list(map(int, [0]*(N-l) + P.bits()))
    return PK(msg).list()
```

`P.bits()` in Sage is **LSB-first**, so `x1` receives bit 0 of the key and `x137` receives bit 136. The generation loop guarantees `KEY.nbits() == 137`, i.e. bit 136 is set — this matters later.

The flag itself is AES-128-ECB under `sha256(str(KEY))`, so recovering `KEY` is the whole game.

---

## 3. Bug #1 — the central map is *linearized*

In a real HFE scheme the central polynomial has the form

```
F(X) = Σ a_ij · X^(q^i + q^j) + Σ b_i · X^(q^i) + c
```

The **quadratic** terms are the ones with exponent `q^i + q^j` — a sum of *two* Frobenius powers. Those are what make the public key a system of quadratic equations, and what make inversion hard.

Here the central map is:

```
F ↦ F^(2q) + F^q + 1  =  F^4 + F^2 + 1
```

With `q = 2`, the exponents are `4 = 2²` and `2 = 2¹`. Both are **single powers of the characteristic** — there is no `q^i + q^j` term anywhere.

A polynomial whose every exponent is a power of `p` is a **linearized (or *p*-polynomial)**. Over GF(2):

```
(A + B)^2 = A^2 + B^2        (Frobenius is a field homomorphism)
```

so `X ↦ X^2` and `X ↦ X^4` are both **GF(2)-linear maps** on `L`. Their sum plus a constant is **GF(2)-affine**. Composing with the affine `S` and `T` leaves the entire public map affine:

```
P(m) = A·m + c        over GF(2)^137
```

The claimed hardness evaporates. No Gröbner basis, no Kipnis–Shamir, no MinRank — just Gaussian elimination.

### Why the polynomials still *look* degree-4

Squaring a coefficient in char 2 distributes over addition, so an affine form squares to a sum of pure squares with no cross terms:

```
(x1 + x5 + x9 + 1)^2 = x1^2 + x5^2 + x9^2 + 1
```

That's exactly what we see in `output.txt` — the public key is full of `x_i^4` and `x_i^2` but **never** a product `x_i·x_j`. A one-line sanity check confirms it across all 137 components:

```python
import re
comps = open('output.txt').readline().strip()[1:-1].split(', ')
forms = {re.sub(r'\d+', '#', t) for c in comps for t in c.split(' + ')}
print(sorted(forms))
# ['#', 'x#^#']     <- only single-variable powers and constants
```

The absence of cross terms *is* the tell. A correct HFE public key would be littered with `x1*x2`-style monomials.

---

## 4. Bug #2 — `H` is built and thrown away

```python
J = ideal([x^q - x for x in R.gens()])
H = R.quotient_ring(J, _vars)     # never referenced again
```

`H` is the **Boolean quotient ring**, where `x_i² = x_i`. It's constructed and then the code keeps working in `R`, so the public polynomials are never reduced and retain their `^4` and `^2` exponents.

This is cosmetic rather than fatal, because the inputs are bits anyway:

```
b ∈ {0, 1}  ⟹  b^4 = b^2 = b
```

So at evaluation time the reduction happens for free. It does mean the printed public key is ~150 KB of noise that would otherwise have been obviously linear at a glance.

---

## 5. Bug #3 — the invertibility check is inverted

```python
if not False in [S_A.is_singular(), T_A.is_singular()]:
    break
```

Python parses this as `not (False in [...])`, which is true only when **both entries are `True`** — i.e. the loop keeps sampling until `S_A` and `T_A` are both **singular**. The intended condition was the opposite.

Consequence: the affine map `A = T_A · L · S_A` is not a bijection. We measured `rank(A) = 135`, leaving a 2-dimensional kernel and 4 candidate preimages. Easy to brute-force, but worth noting — the scheme isn't even correct as a cryptosystem, since decryption would be ambiguous for the legitimate key holder too.

---

## 6. Recovering the affine map

The usual way to linearise a public key is to evaluate it at `0` and at each unit vector `e_i`:

```
c    = P(0)
A[:,i] = P(e_i) - c
```

That's 138 evaluations of a 137-variable polynomial system — slow in Sage and unnecessary here. Since Sage prints the polynomials with like terms already collected, we can just **read the coefficients out of the text**.

For component *j*, the coefficient of `x_i` after Boolean reduction is:

```
A[j][i] = (#{x_i^4 present} + #{x_i^2 present})  mod 2
```

so we XOR-accumulate a bit each time variable *i* appears in any form:

```python
for c in comps:
    r, b = [0]*N, 0
    for term in c.split(" + "):
        m = re.fullmatch(r"x(\d+)(\^\d+)?", term)
        if m:  r[int(m.group(1)) - 1] ^= 1   # x_i^4, x_i^2 and x_i all fold to x_i
        else:  b ^= int(term) & 1            # constant term
    rows.append(r); const.append(b)
```

Parsing 152 KB of text is essentially instant.

---

## 7. Solving

Build the augmented system `A·m = ct ⊕ c` and run Gaussian elimination over GF(2):

```
rank = 135
free vars: x134, x137
```

Rank deficiency of 2 (from Bug #3) gives 4 solutions in the coset `m₀ + ker(A)`. Two filters pin down the right one:

1. **`KEY.bit_length() == 137`** — enforced by the generation loop, so `x137` must be 1.
2. **`b"HTB{" in plaintext`** — decrypt and check.

Reassemble the integer LSB-first (matching `P.bits()`), derive the AES key, decrypt:

```python
KEY = sum(b << i for i, b in enumerate(msg))
AES_KEY = hashlib.sha256(str(KEY).encode()).digest()
pt = AES.new(AES_KEY, AES.MODE_ECB).decrypt(bytes.fromhex(flag_hex))
```

```
KEY = 110621486878801192554077110255801668498185
HTB{e1th3r_gr0bn3r_0r_v4r13ty___1t_st1ll_w0rks!th4nks_f4l4y_f0r_y0ur_4tt4ck_0n_HFE}
```

---

## 8. Full solver

Pure Python, no Sage required. Runs in a couple of seconds.

```python
import re, hashlib, itertools
from Crypto.Cipher import AES

N = 137
lines = open("output.txt").read().split("\n")
comps    = lines[0].strip()[1:-1].split(", ")
target   = [int(v) for v in lines[1].strip()[1:-1].split(", ")]
flag_hex = lines[2].strip()

# --- 1. read the affine map straight out of the printed polynomials ---
rows, const = [], []
for c in comps:
    r, b = [0]*N, 0
    for t in c.split(" + "):
        m = re.fullmatch(r"x(\d+)(\^\d+)?", t)
        if m: r[int(m.group(1)) - 1] ^= 1
        else: b ^= int(t) & 1
    rows.append(r); const.append(b)

# --- 2. Gaussian elimination over GF(2) ---
aug = [rows[j][:] + [target[j] ^ const[j]] for j in range(N)]
piv, r = [], 0
for col in range(N):
    p = next((k for k in range(r, N) if aug[k][col]), None)
    if p is None: continue
    aug[r], aug[p] = aug[p], aug[r]
    for k in range(N):
        if k != r and aug[k][col]:
            aug[k] = [a ^ b for a, b in zip(aug[k], aug[r])]
    piv.append(col); r += 1
free = [c for c in range(N) if c not in piv]
print("rank =", r, "| free vars:", [f+1 for f in free])

def build(fv):
    m = [0]*N
    for c, v in zip(free, fv): m[c] = v
    for i, col in enumerate(piv):
        m[col] = aug[i][N] ^ (sum(aug[i][c] & m[c] for c in free) & 1)
    return m

# --- 3. enumerate the coset, filter on nbits == 137 and the flag prefix ---
for fv in itertools.product([0, 1], repeat=len(free)):
    m = build(fv)
    assert all((sum(rows[j][i] & m[i] for i in range(N)) ^ const[j]) & 1 == target[j]
               for j in range(N))
    KEY = sum(b << i for i, b in enumerate(m))   # P.bits() is LSB-first
    if KEY.bit_length() != N: continue
    pt = AES.new(hashlib.sha256(str(KEY).encode()).digest(),
                 AES.MODE_ECB).decrypt(bytes.fromhex(flag_hex))
    if b"HTB{" in pt:
        print("KEY =", KEY)
        print(pt[:-pt[-1]].decode())
```

---

## 9. Takeaways

- **Check the exponents in any HFE-style central map.** If every exponent is a power of the characteristic, the map is linearized and the scheme is affine. Security requires at least one `q^i + q^j` term.
- **No cross terms in a multivariate public key ⇒ it isn't multivariate.** Grep for `x_i*x_j` before reaching for Gröbner bases; a quick `re.sub(r'\d+','#',term)` over the monomial set answers it in one line.
- **Parse, don't evaluate.** When Sage has already printed the collected polynomials, reading coefficients from text beats 138 symbolic evaluations.
- **Read boolean conditions carefully.** `not False in [a, b]` means "both are True" — here it selected *singular* matrices, silently breaking the scheme's bijectivity.
- The flag's own joke is the real lesson: **Gröbner basis** attacks (Faugère–Joux) and **variety/structural** attacks (Kipnis–Shamir MinRank) both break HFE in practice. This instance simply didn't need either.
