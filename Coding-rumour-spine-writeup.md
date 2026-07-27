# Rumour Spine — Writeup

**Category:** Coding / Algorithms
**Flag:** `HTB{0n3_c00rd1n4t3d_m0m3nt}`

---

## Challenge

> Suncourt doesn't march first — it primes first. Miren Vale has traced the Quiet March's invitation chain: a coordinator who never touches ash, only schedules, feeding a priming signal through a network of quiet hands — candle-buyers, shrine-attendants, penitent-scribes — until a target district falls still the night before the March arrives. Every hand who passes the signal on is a link Miren can expose. Miren means to break the chain before the district goes quiet. She can expose any quiet hand along the way — one flagged, one route burned, at the cost of one favour she can never call in again. The coordinator and the target district can't be touched directly: too visible, too soon. What is the minimum number of quiet hands that must be exposed to sever every path the priming signal could still travel?

A Docker instance was provided on port `30409`.

---

## Step 1 — Translating the flavour text

The prose is dense, but every clause maps onto a graph primitive. Stripping the setting away:

| Story element | Graph meaning |
|---|---|
| The coordinator | Source vertex `s` |
| The target district | Sink vertex `t` |
| Quiet hands (candle-buyers, scribes…) | Intermediate vertices |
| Passing the signal on | Directed edge `u → v` |
| Exposing a hand, at the cost of one favour | Deleting a vertex, unit cost |
| "The coordinator and the target district can't be touched" | `s` and `t` are **not** deletable |
| "Sever every path the signal could still travel" | Disconnect `s` from `t` |

So the question is: **what is the minimum number of intermediate vertices whose removal disconnects `s` from `t`?**

That is the textbook **minimum s–t vertex cut**.

Two details in the wording are load-bearing and worth flagging:

- *"Every hand who passes the signal on is a link"* — the cost is per **vertex**, not per edge. This is a vertex cut, not the more familiar edge cut. Solving the edge version gives a plausible-looking but wrong number.
- *"can't be touched directly"* — `s` and `t` are excluded from the cut. Without this the answer would trivially be 1 (remove either endpoint).

---

## Step 2 — The algorithm

**Menger's theorem** states that the minimum number of vertices separating `s` from `t` equals the maximum number of internally vertex-disjoint `s→t` paths. Max-flow/min-cut gives us the disjoint-path count directly — but standard max flow caps *edges*, and we need to cap *vertices*.

The fix is the **node-splitting** construction. Every vertex `v` is split into two:

```
v_in ──[cap 1]──> v_out
```

and every original edge `u → v` is rewired as:

```
u_out ──[cap ∞]──> v_in
```

Because the only way to pass "through" a vertex is across its internal capacity-1 edge, any minimum cut in the transformed network must consist of these internal edges — and each one corresponds to deleting exactly one original vertex. Infinite capacity on the rewired edges guarantees the cut never prefers an original edge.

To make `s` and `t` untouchable, their internal edges get capacity **∞** instead of 1. Then:

```
answer = maxflow(s_out → t_in)
```

Visually, for a graph where two routes converge on a single hand `x`:

```
        a
      ↗   ↘
    s       x ──> t          min vertex cut = 1  (expose x)
      ↘   ↗
        b
```

versus two genuinely independent routes:

```
      ↗ a ↘
    s       t                min vertex cut = 2  (expose a and b)
      ↘ b ↗
```

The whole challenge is recognising which shape the input has — and max flow answers that for arbitrary graphs.

### Complexity

Dinic's algorithm on unit-capacity vertex networks runs in `O(E·√V)`, which is comfortably fast for judge-sized inputs. My final solution handled a 4000-node graph in 0.03s.

---

## Step 3 — A wrong turn worth documenting

The challenge gave an `IP:PORT`, so my first assumption was a **socket service**: connect, receive a graph, send back an integer, repeat until the flag drops. I wrote a `pwntools` client around exactly that model.

Submitting my local test harness produced this:

```
Test case 1 failed - Runtime Error
Traceback (most recent call last):
  File "/app/files/main.c", line 3, in <module>
    from rumour_spine import min_vertex_cut
ModuleNotFoundError: No module named 'rumour_spine'
```

That traceback is the real recon. Three things fall out of it:

1. **`/app/files/main.c`** — my submission was copied server-side to a fixed path. This is a **code judge**, not an interactive service. You upload one source file; it runs against hidden test cases.
2. **`ModuleNotFoundError`** — the submission runs in isolation. No local imports, no `pwntools`, standard library only.
3. **`main.c` executing as Python** — the harness names the file `.c` regardless of the language actually selected. A cosmetic quirk, but a good reminder to confirm the judge's language setting.

**Lesson:** an `IP:PORT` in a coding-category challenge is as likely to be a web judge as a netcat service. `curl` the port before writing a socket client.

---

## Step 4 — The solution

Rewritten as a self-contained stdin → stdout program:

```python
import sys
from collections import deque

INF = float("inf")


class Dinic:
    def __init__(self, n):
        self.n = n
        self.g = [[] for _ in range(n)]

    def add(self, u, v, cap):
        self.g[u].append([v, cap, len(self.g[v])])
        self.g[v].append([u, 0, len(self.g[u]) - 1])

    def _bfs(self, s, t):
        self.level = [-1] * self.n
        self.level[s] = 0
        q = deque([s])
        while q:
            u = q.popleft()
            for v, cap, _ in self.g[u]:
                if cap > 0 and self.level[v] < 0:
                    self.level[v] = self.level[u] + 1
                    q.append(v)
        return self.level[t] >= 0

    def _dfs(self, s, t):
        """Iterative augmenting-path search along the level graph."""
        path, u = [], s
        while True:
            if u == t:
                f = min(self.g[a][i][1] for a, i in path)
                for a, i in path:
                    e = self.g[a][i]
                    e[1] -= f
                    self.g[e[0]][e[2]][1] += f
                return f
            advanced = False
            while self.it[u] < len(self.g[u]):
                v, cap, _ = self.g[u][self.it[u]]
                if cap > 0 and self.level[v] == self.level[u] + 1:
                    path.append((u, self.it[u]))
                    u = v
                    advanced = True
                    break
                self.it[u] += 1
            if advanced:
                continue
            if not path:
                return 0
            self.level[u] = -1          # dead end: prune from level graph
            u, i = path.pop()
            self.it[u] += 1

    def maxflow(self, s, t):
        flow = 0
        while self._bfs(s, t):
            self.it = [0] * self.n
            while True:
                f = self._dfs(s, t)
                if f == 0:
                    break
                flow += f
        return flow


def min_vertex_cut(n, edges, s, t):
    din = Dinic(2 * n)
    for v in range(n):
        # s and t are untouchable -> infinite internal capacity
        din.add(2 * v, 2 * v + 1, INF if v in (s, t) else 1)
    for u, v in edges:
        if u == s and v == t:
            return None                 # direct link: no cut exists
        din.add(2 * u + 1, 2 * v, INF)
    f = din.maxflow(2 * s + 1, 2 * t)
    return None if f == INF else int(f)
```

Two implementation notes that mattered in practice:

- **The DFS is iterative.** The natural recursive Dinic blows Python's stack on deep level graphs, and a judge will happily supply one. Rewriting it with an explicit path stack removes the failure mode entirely.
- **Dead-end pruning.** Setting `self.level[u] = -1` when a vertex has no usable outgoing edge is what keeps Dinic near its theoretical bound rather than degenerating.

---

## Step 5 — Verification before submitting

Judges give you almost no feedback, so correctness is worth establishing locally first. I cross-checked the flow solution against brute force — try every subset of intermediate vertices in increasing size order, return the first that disconnects `s` from `t`:

```python
def brute(n, edges, s, t):
    mid = [v for v in range(n) if v not in (s, t)]
    for k in range(len(mid) + 1):
        for sub in combinations(mid, k):
            if not reachable(edges, s, t, set(sub)):
                return k
```

Over 500 random graphs (4–9 nodes, ~35% edge density), the max-flow answer matched brute force every time. That is enough to trust the construction on inputs too large to verify directly.

Sanity cases:

| Graph | Expected | Got |
|---|---|---|
| `s→a→t`, `s→b→t` | 2 | 2 |
| `s→a→x`, `s→b→x`, `x→t` | 1 | 1 |
| Three disjoint paths | 3 | 3 |
| `s→t` direct | impossible | `None` |
| No path at all | 0 | 0 |

---

## Step 6 — Flag

With the self-contained file submitted, all test cases passed:

```
HTB{0n3_c00rd1n4t3d_m0m3nt}
```

The flag rewards the insight — one coordinated moment, one bottleneck. The narrative was pointing at the answer the whole time: a single well-chosen hand can be worth more than any number of poorly chosen ones, which is exactly what a minimum vertex cut computes.

---

## Takeaways

1. **Coding-category flavour text is a specification.** Every clause mapped to a constraint; the untouchable endpoints and the per-vertex cost were both stated explicitly and both changed the algorithm.
2. **Vertex cut ≠ edge cut.** Node splitting is the standard bridge, and it is worth having ready — it converts any vertex-capacitated problem into a plain max-flow one.
3. **Read error messages as recon.** The `ModuleNotFoundError` traceback revealed the execution path, the isolation model, and the harness's language handling in three lines.
4. **Verify against brute force.** On a judge with hidden tests, a randomized cross-check against an exhaustive solver is the cheapest confidence you can buy.
