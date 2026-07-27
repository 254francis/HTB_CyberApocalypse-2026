# Cinderbound — Reverse Engineering Write-up

**Category:** Reverse Engineering
**Provided file:** `cinderbound.mpy` (221 bytes)
**Flag:** `c1nd3rbound_v0w5`

---

## 0. Summary

The challenge ships a single MicroPython bytecode module containing a `judge(syllable)` function that validates a candidate string. The check is a rolling-state stream cipher whose keystream is derived from the **plaintext** rather than the ciphertext, which makes it trivially invertible byte-by-byte from a known starting state. No brute force is needed — the flag falls out of a 6-line decoder.

The lengthy ASHVAULT/CROWQUILL narrative in the prompt is series flavour text. Nothing in the supplied artifact is a disk image or registry hive, so the 7-Zip forensic angle it describes does not apply to this file.

---

## 1. Recon

Unpack and identify:

```bash
unzip challenge.zip -d extracted
find extracted -type f
# extracted/cinderbound.mpy

file extracted/cinderbound.mpy
# cinderbound.mpy: data
```

`file` doesn't recognise it, so go straight to the bytes:

```bash
od -A x -t x1z extracted/cinderbound.mpy
```

```
000000  4d 06 00 1f 08 01 18 6a 75 64 67 65 5f 73 72 63  >M......judge_src<
000010  2e 70 79 00 0f 0a 6a 75 64 67 65 00 79 10 73 79  >.py...judge.y.sy<
000020  6c 6c 61 62 6c 65 00 81 57 81 6f 81 59 0a 10 07  >llable..W.o.Y...<
000030  02 35 37 07 03 31 32 39 07 03 31 35 34 07 02 33  >.57..129..154..3<
...
```

Two things identify the format immediately:

- **Magic byte `0x4D` (`'M'`)** followed by a version byte — this is MicroPython's `.mpy` header. Here `4d 06 00 1f` = magic `M`, **mpy format version 6**, feature flags `0x00`, small-int bits `0x1f` (31).
- Readable qstrs in the header: `judge_src.py`, `judge`, `syllable`.

Format v6 corresponds to MicroPython ~1.19 through 1.22.

Also visible in the dump: a run of ASCII decimal numbers (`57`, `129`, `154`, `31`, ...). In `.mpy` v6, constant tuples of small ints are serialised in this decimal-string form, so this is almost certainly the comparison target.

---

## 2. Tooling

You do **not** need to build the MicroPython interpreter. The repo ships `tools/mpy-tool.py`, which disassembles `.mpy` files directly, as long as the tool version matches the format version.

```bash
git clone --depth 1 --branch v1.22.2 https://github.com/micropython/micropython.git mp
python3 mp/tools/mpy-tool.py -d extracted/cinderbound.mpy
```

> If the tool errors with a version mismatch, check byte 1 of the file and clone a tag whose `MPY_VERSION` matches (v6 → 1.19.1–1.22.x, v5 → 1.12–1.18).

---

## 3. Disassembly

Header and constants:

```
source_file: judge_src.py
header: 4d:06:00:1f
qstr_table[8]:
    judge_src.py
    <module>
    judge
    append
    syllable
    len
    ord
    list
obj_table: [(57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)]
```

The module body is trivial — define the function, bind the name, return:

```
32:00       MAKE_FUNCTION 0
16:02       STORE_NAME judge
51          LOAD_CONST_NONE
63          RETURN_VALUE
```

The `judge` body, annotated:

```
23:00       LOAD_CONST_OBJ (57, 129, ... 67, 15)
c1          STORE_FAST 1              ; local1 = target tuple
22:80:5a    LOAD_CONST_SMALL_INT 90
c2          STORE_FAST 2              ; local2 = state = 90
2b:00       BUILD_LIST 0
c3          STORE_FAST 3              ; local3 = out = []

12:05       LOAD_GLOBAL len           ; --- for i in range(len(syllable)) ---
b0          LOAD_FAST 0
34:01       CALL_FUNCTION 1
80          LOAD_CONST_SMALL_INT 0
42:6b       JUMP 43
57          DUP_TOP
c4          STORE_FAST 4              ; local4 = i

12:06       LOAD_GLOBAL ord           ; --- c = (ord(s[i]) ^ state) ^ ((i*13)&255) ---
b0          LOAD_FAST 0
b4          LOAD_FAST 4
55          LOAD_SUBSCR               ; syllable[i]
34:01       CALL_FUNCTION 1           ; ord(syllable[i])
b2          LOAD_FAST 2               ; state
ee          BINARY_OP 23 __xor__
b4          LOAD_FAST 4               ; i
8d          LOAD_CONST_SMALL_INT 13
f4          BINARY_OP 29 __mul__      ; i * 13
22:81:7f    LOAD_CONST_SMALL_INT 255
ef          BINARY_OP 24 __and__      ; (i*13) & 255
ee          BINARY_OP 23 __xor__
c5          STORE_FAST 5              ; local5 = c

b2          LOAD_FAST 2               ; --- state = (state + ord(s[i])) & 255 ---
12:06       LOAD_GLOBAL ord
b0          LOAD_FAST 0
b4          LOAD_FAST 4
55          LOAD_SUBSCR
34:01       CALL_FUNCTION 1
f2          BINARY_OP 27 __add__
22:81:7f    LOAD_CONST_SMALL_INT 255
ef          BINARY_OP 24 __and__
c2          STORE_FAST 2

b3          LOAD_FAST 3               ; out.append(c)
14:03       LOAD_METHOD append
b5          LOAD_FAST 5
36:01       CALL_METHOD 1
59          POP_TOP

81          LOAD_CONST_SMALL_INT 1    ; loop increment + back-edge
e5          BINARY_OP 14 __iadd__
58          DUP_TOP_TWO
5a          ROT_TWO
d7          BINARY_OP 0 __lt__
43:10       POP_JUMP_IF_TRUE -48
59          POP_TOP
59          POP_TOP

b3          LOAD_FAST 3               ; return out == list(target)
12:07       LOAD_GLOBAL list
b1          LOAD_FAST 1
34:01       CALL_FUNCTION 1
d9          BINARY_OP 2 __eq__
63          RETURN_VALUE
```

### Notes on reading the loop

The `LOAD_GLOBAL len / CALL / LOAD_CONST 0 / JUMP` + `DUP_TOP_TWO / ROT_TWO / __lt__ / POP_JUMP_IF_TRUE` sandwich is MicroPython's optimised `for i in range(n)` idiom. Recognising it saves time — the bound and counter live on the stack rather than in named locals, so it looks stranger than it is.

`STORE_FAST n` opcodes are the single bytes `0xC0 + n`, and `LOAD_FAST n` is `0xB0 + n`, which makes mapping locals to slot numbers quick.

---

## 4. Reconstructed source

```python
def judge(syllable):
    target = (57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)
    state = 90
    out = []
    for i in range(len(syllable)):
        c = (ord(syllable[i]) ^ state) ^ ((i * 13) & 255)
        state = (state + ord(syllable[i])) & 255
        out.append(c)
    return out == list(target)
```

---

## 5. The weakness

Each output byte is masked with two values:

- `(i * 13) & 255` — a positional constant, known to the attacker for free.
- `state` — a running sum of all **plaintext** bytes seen so far, mod 256.

The critical flaw is that `state` at step `i` depends only on bytes `0..i-1` of the plaintext, and the seed `state = 90` is hardcoded. So the decode is causal and self-feeding: recover byte `i`, use it to advance `state`, recover byte `i+1`.

Had the state been fed from the *ciphertext* — or had a single unknown byte been mixed into the seed — this would have needed a 256-way search per candidate chain. As written, it's a single deterministic pass with zero branching.

The target tuple is 16 entries, so the answer is 16 characters. Nothing needs to be guessed.

### Inversion

```
ord(s[i]) = target[i] ^ ((i * 13) & 255) ^ state_i
state_{i+1} = (state_i + ord(s[i])) & 255
state_0 = 90
```

---

## 6. Solve script

`solve.py`:

```python
target = (57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)

state = 90
plain = []
for i, c in enumerate(target):
    ch = (c ^ ((i * 13) & 255)) ^ state
    plain.append(ch)
    state = (state + ch) & 255

s = "".join(chr(b) for b in plain)
print("recovered:", s)


# re-implement the original check to verify
def judge(syllable):
    state = 90
    out = []
    for i in range(len(syllable)):
        c = (ord(syllable[i]) ^ state) ^ ((i * 13) & 255)
        state = (state + ord(syllable[i])) & 255
        out.append(c)
    return out == list(target)


print("judge() ->", judge(s))
```

```bash
$ python3 solve.py
recovered: c1nd3rbound_v0w5
judge() -> True
```

The round-trip through a re-implementation of the original `judge` is worth keeping — it catches an off-by-one in the position mask or a misread `state` update immediately, rather than after you've burned a flag submission.

---

## 7. Flag

```
c1nd3rbound_v0w5
```

Wrap in the event's format, e.g. `flag{c1nd3rbound_v0w5}`.

---

## 8. Takeaways

- **`4D` + a low version byte at offset 0 means MicroPython `.mpy`.** `file` won't tell you. Byte 1 is the format version and dictates which `mpy-tool.py` you need.
- **`mpy-tool.py -d` beats building the interpreter** for static checkers like this one. Cloning the matching tag is a 10-second job.
- **Trace where the keystream state comes from.** Plaintext-fed state is invertible in one pass; ciphertext-fed or externally-seeded state is not. That single detail decides whether the challenge is a 6-line script or a search problem.
- **Readable constants in a hex dump are a shortcut.** The decimal-string encoding of the int tuple in the `.mpy` object table gave up the comparison target before any disassembly happened.
