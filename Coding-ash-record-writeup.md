# Ash Record — HTB Coding Challenge Writeup

**Category:** Coding
**Flag:** `HTB{th3_h4ml3t_w4s_k3pt_n0t_burn3d}`

---

## 1. Reading the prompt

The challenge text is heavy on flavour — a riverside hamlet emptied mid-meal, Elowen Ashglass reading soot and drag-marks as a "staged confession." The narrative is a wrapper. The last two sentences carry the entire specification:

> She has recovered residues across the site, each carrying a timestamp and a material type. She also holds the extraction sequence she suspects was followed... She needs the longest prefix of that sequence she can actually confirm: a subsequence of residues matching it in order, where no two consecutively matched residues are closer together than a minimum gap.

Stripped down:

- **Input:** a multiset of residues `(timestamp, material)`, a pattern sequence of materials, and an integer `g`.
- **Task:** find the largest `L` such that `sequence[0..L-1]` can be matched as a subsequence of the residues sorted by timestamp, subject to `t[i+1] - t[i] >= g` between consecutive matched residues.
- **Output:** the integer `L`.

Two details matter and are easy to skim past:

1. It asks for the longest **prefix**, not the longest subsequence. You stop at the first pattern element you cannot place — you don't skip it and keep going.
2. The residues are *not* guaranteed to arrive in timestamp order. They didn't, in the actual test data.

## 2. Choosing the algorithm

The instinct on a "match a pattern as a subsequence with constraints" problem is DP, but that's unnecessary here. **Greedy earliest-feasible matching is optimal.**

For each pattern element in order, pick the residue of that material with the *smallest* timestamp satisfying `t >= prev + g`.

*Proof sketch (exchange argument):* let `G[i]` be the timestamp greedy assigns to pattern element `i`, and `S[i]` the timestamp any valid solution assigns. Claim `G[i] <= S[i]` for all `i`, by induction. Base case: greedy takes the globally earliest residue of the right material, so `G[0] <= S[0]`. Inductive step: assuming `G[i-1] <= S[i-1]`, the feasibility threshold for greedy is `G[i-1] + g <= S[i-1] + g`, so every residue available to the solution is also available to greedy; greedy takes the earliest of a superset, hence `G[i] <= S[i]`. Therefore if any solution reaches length `L`, greedy reaches at least `L`. The constraint is monotone in the previous timestamp, which is exactly what makes this work.

**Implementation:** bucket timestamps by material into sorted lists, then `bisect_left` for the threshold on each step. That gives O((n + m) log n) — far more headroom than needed, but it costs nothing to write.

## 3. First attempt — wrong input format

I assumed JSON on stdin and got:

```
json.decoder.JSONDecodeError: Extra data: line 1 column 4 (char 3)
```

Worth reading that error properly rather than just discarding the parser. `json.loads` successfully consumed characters 0–2 and then hit trailing content, meaning **line 1 begins with a 3-character integer token followed by more data**. That already tells you it's whitespace-delimited plain text with a numeric header.

## 4. Recovering the format

The HTB harness echoes stdout even on a failed test case, which makes it a free input oracle. Submitting a program that only dumps stdin:

```python
import sys

raw = sys.stdin.read()
lines = raw.splitlines()

print("total_len:", len(raw))
print("num_lines:", len(lines))
for i, ln in enumerate(lines[:12]):
    print(i, repr(ln[:200]))
```

Returned:

```
total_len: 99 num_lines: 12
0 '10 3 4'
1 'rope ash tallow'
2 '9 pine'
3 '18 iron'
4 '58 ash'
5 '1 pine'
6 '22 ash'
7 '7 rope'
8 '28 tallow'
9 '46 iron'
10 '14 rope'
11 '40 iron'
```

So the format is:

```
n m g
<m materials, space-separated>   <- the extraction sequence
<timestamp> <material>           <- n lines of residues, unsorted
...
```

Here `n = 10` residues, `m = 3` sequence stages, `g = 4` minimum gap.

## 5. Verifying the gap semantics by hand

"No two consecutively matched residues are closer together than a minimum gap" is ambiguous between `>=` and `>`. The sample resolves it — expected output was `3`.

Residues sorted by timestamp:

| t | material |
|---|----------|
| 1 | pine |
| 7 | rope |
| 9 | pine |
| 14 | rope |
| 18 | iron |
| 22 | ash |
| 28 | tallow |
| 40 | iron |
| 46 | iron |
| 58 | ash |

Pattern `rope → ash → tallow`, `g = 4`:

- `rope`: earliest is **t=7**.
- `ash`: need `t >= 7 + 4 = 11`. Candidates are 22 and 58 → take **t=22**.
- `tallow`: need `t >= 22 + 4 = 26`. Only tallow is at 28, and `28 >= 26` → take **t=28**.

All 3 stages place, matching the expected `3`. Note this case doesn't discriminate `>=` from `>` (28 > 26 either way), but it confirmed the greedy and the parse, and the full test set passed with `>=`.

## 6. Final solution

```python
import sys
from bisect import bisect_left
from collections import defaultdict


def longest_prefix(residues, sequence, min_gap):
    buckets = defaultdict(list)
    for t, m in sorted(residues):
        buckets[m].append(t)

    prev = None
    matched = 0
    for mat in sequence:
        times = buckets.get(mat)
        if not times:
            break
        idx = 0 if prev is None else bisect_left(times, prev + min_gap)
        if idx >= len(times):
            break
        prev = times[idx]
        matched += 1
    return matched


def main():
    tok = sys.stdin.read().split()
    p = 0
    n, m, g = int(tok[p]), int(tok[p + 1]), int(tok[p + 2])
    p += 3
    sequence = tok[p:p + m]
    p += m
    residues = []
    for _ in range(n):
        residues.append((int(tok[p]), tok[p + 1]))
        p += 2
    print(longest_prefix(residues, sequence, g))


if __name__ == "__main__":
    main()
```

Reading by whitespace tokens rather than by line means the parser survives any test case that wraps the sequence or residue list differently — a cheap hedge on a format you only ever saw one example of.

All test cases passed, yielding:

```
HTB{th3_h4ml3t_w4s_k3pt_n0t_burn3d}
```

## 7. Takeaways

- **Translate the flavour text into a formal spec before writing any code.** The whole challenge is one greedy loop; the difficulty is entirely in reading carefully enough to notice "prefix" (not "subsequence") and that the input is unsorted.
- **Parse the exception, don't just replace the parser.** `Extra data: char 3` pinned the header shape before I'd seen a single byte of real input.
- **A harness that echoes stdout on failure is an input oracle.** Burning one submission on a dump script is almost always faster than guessing formats.
- **Check whether greedy suffices before reaching for DP.** Monotone feasibility constraints usually admit an exchange argument.
