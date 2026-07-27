# Vow Engine — Writeup

**Category:** Coding / Algorithms
**Flag:** `HTB{th3_b3ll_r1ngs_wr0ng_0n_purp0s3}`

---

## 1. Reading the flavor text

The prose is dense, but every clause maps onto a concrete piece of the problem. Stripping the story out:

| Flavor | Technical meaning |
|---|---|
| "a network of witnesses linked by seal-marks" | An undirected graph: witnesses = nodes, seal-marks = edges |
| "every seal-mark carries a cadence key" | Each edge has an integer weight |
| "the XOR of every cadence key along the path" | Path value = XOR of edge weights, not the sum |
| "redundant links on purpose: no single failure point" | The graph contains **cycles** |
| "a pair of witnesses can be connected by more than one oath-path, and different paths can combine to different cadence values" | Multiple achievable values per node pair — this is the whole challenge |
| "for each of Q live challenges … answer instantly" | Q queries, must be sublinear per query after preprocessing |

So the actual task: given a weighted undirected graph and queries `(u, v, k)`, decide whether some path from `u` to `v` has XOR-weight exactly `k`.

### The key inference: paths are walks

"Path" is doing important work here. If it meant a **simple** path (no repeated vertices), the problem is NP-hard and there is no "answer instantly" solution — you cannot preprocess your way out of it for large Q.

The flavor text insists on instant answers, which is itself the hint: repeated vertices must be allowed. We're dealing with **walks**, and walks have beautiful linear-algebraic structure that simple paths do not.

---

## 2. The mathematics

Work in GF(2)^b — bit vectors of width `b` under XOR. XOR is addition in this field, which is what makes the whole thing linear.

### Step 1: Fix a spanning forest

For each connected component, pick a root and run a DFS/BFS. Define

> `d[x]` = XOR of weights along the tree path from the root to `x`

### Step 2: Any tree path value is a difference

For two nodes `u`, `v` in the same component, the tree path from `u` to `v` has value `d[u] ^ d[v]`. The shared prefix from the root down to their LCA appears in both terms and cancels, since `a ^ a = 0`. No LCA computation needed — the cancellation is automatic.

### Step 3: Detours form a vector space

Any walk from `u` to `v` can be decomposed into the tree path plus some collection of cycles traversed along the way. Traversing a cycle and returning contributes that cycle's XOR value to the total. Traversing it twice contributes nothing (`c ^ c = 0`), which is exactly why walks are so much friendlier than simple paths.

The set of all achievable cycle contributions is the **cycle space** of the component — a vector subspace over GF(2). It is spanned by the *fundamental cycles*: for every non-tree edge `(a, b, w)`, the cycle formed by that edge plus the tree path between its endpoints has value

```
cycle_value = d[a] ^ d[b] ^ w
```

### Step 4: The answer is a coset membership test

Putting it together, the set of achievable values from `u` to `v` is the coset

```
{ d[u] ^ d[v] ^ c  :  c ∈ CycleSpace }
```

So `k` is achievable **iff**:

1. `u` and `v` are in the same connected component, **and**
2. `k ^ d[u] ^ d[v]` lies in the cycle space.

Test (2) with a **linear XOR basis** (Gaussian elimination over GF(2)), keeping one basis vector per leading bit position. Reduce the target by repeatedly XORing with the basis vector matching its highest set bit; if it reaches 0, it's in the span.

Preprocessing is O((n + m)·b), each query is O(b) — roughly 64 operations regardless of graph size. That's the "instant" answer the rite demands.

### A useful invariant

The choice of spanning tree is arbitrary and different DFS orderings give different `d[]` arrays — but the cycle space, and therefore every answer, is identical. This is worth knowing because it means you cannot debug by comparing `d[]` values against someone else's solution; only the final coset is canonical.

---

## 3. Worked example on the sample test case

The judge's first test case:

```
5 6 4
2 1 10
1 4 44
4 3 3
3 0 9
0 4 15
3 2 39
1 1 27
3 4 7
0 1 45
1 1 18
```

Five nodes, six edges, four queries. Rooting at node 0 and running DFS:

```
tree edge 0-3 (w=9)    d[3] = 0 ^ 9  = 9
tree edge 0-4 (w=15)   d[4] = 0 ^ 15 = 15
tree edge 4-1 (w=44)   d[1] = 15 ^ 44 = 35
tree edge 1-2 (w=10)   d[2] = 35 ^ 10 = 41

d[] = [0, 35, 41, 9, 15]
```

Fundamental cycles from the non-tree edges:

```
edge 4-3 w=3    ->  15 ^ 9  ^ 3  = 5
edge 3-2 w=39   ->   9 ^ 41 ^ 39 = 7
```

(The remaining edges are tree edges and yield 0, as they must.)

Inserting into the basis: 5 = `0b101` lands at bit 2. Then 7 = `0b111` collides at bit 2, reduces to `7 ^ 5 = 2` = `0b10`, and lands at bit 1.

```
basis = {5, 2}
cycle space = {0, 2, 5, 7}
```

Now the queries:

| Query | Target = `k ^ d[u] ^ d[v]` | In span? | Answer |
|---|---|---|---|
| `(1, 1, 27)` | `27 ^ 35 ^ 35 = 27` | no | NO |
| `(3, 4, 7)`  | `7 ^ 9 ^ 15 = 1`   | no | NO |
| `(0, 1, 45)` | `45 ^ 0 ^ 35 = 14` | no | NO |
| `(1, 1, 18)` | `18 ^ 35 ^ 35 = 18` | no | NO |

Matches the expected `NO NO NO NO`.

Note query 1 and 4: `u == v`, so the target is just `k` itself. A self-query asks purely whether `k` is a reachable cycle value — the empty walk covers `k = 0`, which the formula handles for free.

---

## 4. The false start (and how the failure recovered the format)

My first attempt assumed the Docker instance spoke a **socket protocol** — connect with pwntools, parse a banner, stream answers back interactively. That was a wrong read of "docker instance" for this challenge type, and it cost a submission.

The failed submission is what gave the format away. The judge reported:

```
Test case 1 failed - Wrong answer
Input:  5 6 4 2 1 10 1 4 44 ...
Output: all self-tests passed
Expected: NO NO NO NO
```

Three things fell out of that error message:

1. **"Output: all self-tests passed"** — the judge had executed the local stress-test harness rather than the solver, which confirmed it runs an uploaded script against **stdin/stdout**. Not a network service at all.
2. **Token counting recovered the input layout.** The input has 33 whitespace-separated integers. Trying `n=5, m=6, q=4` gives `3 + 3·6 + 3·4 = 33` — an exact fit. So all three counts sit on the first line, before the edges. My socket version had guessed `q` came *after* the edge list.
3. **Node ids run 0–4 with n=5**, so the graph is **0-indexed**. The socket version had assumed 1-indexed.

Lesson worth keeping: a judge that echoes the failing input is leaking the format specification. Token arithmetic on a single sample is usually enough to pin the layout down completely.

---

## 5. Solution

```python
import sys


def main():
    data = sys.stdin.buffer.read().split()
    if not data:
        return
    pos = 0

    def nxt():
        nonlocal pos
        v = int(data[pos])
        pos += 1
        return v

    n, m, q = nxt(), nxt(), nxt()

    edges = []
    maxid = n - 1
    for _ in range(m):
        u, v, w = nxt(), nxt(), nxt()
        edges.append((u, v, w))
        if u > maxid:
            maxid = u
        if v > maxid:
            maxid = v

    size = maxid + 1              # tolerant of 0- or 1-indexed input
    adj = [[] for _ in range(size)]
    for u, v, w in edges:
        adj[u].append((v, w))
        adj[v].append((u, w))

    comp = [-1] * size            # component id per node
    d = [0] * size                # XOR distance from component root
    bases = []                    # one XOR basis per component

    for s in range(size):
        if comp[s] != -1:
            continue
        c = len(bases)
        basis = {}
        bases.append(basis)
        comp[s] = c
        stack = [s]
        while stack:                          # iterative: no recursion limit
            x = stack.pop()
            dx = d[x]
            for y, w in adj[x]:
                if comp[y] == -1:             # tree edge
                    comp[y] = c
                    d[y] = dx ^ w
                    stack.append(y)
                else:                         # non-tree edge -> fundamental cycle
                    cyc = dx ^ d[y] ^ w
                    while cyc:
                        b = cyc.bit_length() - 1
                        if b not in basis:
                            basis[b] = cyc
                            break
                        cyc ^= basis[b]

    out = []
    for _ in range(q):
        u, v, k = nxt(), nxt(), nxt()
        if comp[u] != comp[v]:
            out.append("NO")
            continue
        x = k ^ d[u] ^ d[v]
        basis = bases[comp[u]]
        while x:
            b = x.bit_length() - 1
            if b not in basis:
                break
            x ^= basis[b]
        out.append("YES" if x == 0 else "NO")

    sys.stdout.write("\n".join(out) + "\n")


main()
```

Implementation notes:

- **Iterative DFS.** Recursion blows the stack on large components.
- **Basis as a dict keyed by leading bit.** Avoids fixing a bit width in advance, so 62-bit weights need no special handling.
- **`size = maxid + 1`.** Sizing off the largest node id seen rather than `n` makes the solution work under either indexing convention — cheap insurance against exactly the mistake that cost the first submission.
- **Bulk I/O.** `sys.stdin.buffer.read().split()` rather than per-line reads; with ~1.8M tokens, line-by-line parsing dominates the runtime.

---

## 6. Verification before resubmitting

Two checks, both worth doing before spending another submission:

**Correctness against brute force.** For small graphs, enumerate all reachable `(node, accumulated_xor)` states with BFS — the state space is bounded, so this exhaustively covers every walk. Compare against the linear-algebra answer over 200 random graphs (self-loops, multi-edges, and disconnected components included). All 200 matched.

**Performance.** 200k nodes / 400k edges / 200k queries with 62-bit weights ran in ~6.2s in CPython. Every query returned YES, which is the expected degenerate behavior: with that many random extra edges the basis reaches full rank and spans the entire value space.

If a tighter time limit had bitten, the two available wins were flattening the adjacency list into CSR arrays, and short-circuiting basis insertion once the rank hits the weight bit width — beyond that point every same-component query is YES regardless.

---

## 7. Takeaways

- **XOR path queries on a general graph = coset of the cycle space.** Spanning forest for `d[]`, fundamental cycles for the basis, one reduction per query. This is a reusable pattern; the same machinery solves "maximize XOR path value" by greedily reducing against the basis from the top bit down.
- **"Instantly" in a problem statement is a complexity constraint in disguise.** It was the tell that walks, not simple paths, were intended — the simple-path version is NP-hard and cannot be answered instantly at scale.
- **A judge that echoes failing input is leaking its own spec.** Token-count arithmetic on one sample pinned down the layout and the indexing convention without any further guessing.
- The flag, `th3_b3ll_r1ngs_wr0ng_0n_purp0s3`, is a nod to the mechanic: the redundant links are deliberate, and the "wrong" alternate paths are precisely what make multiple cadence values reachable.
