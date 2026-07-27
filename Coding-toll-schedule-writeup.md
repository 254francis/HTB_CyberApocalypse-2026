# Toll Schedule — HTB Writeup

**Category:** Coding / Algorithms
**Flag:** `HTB{th3_p4ss_pr3f3rs_0n3_b4nn3r}`

---

## The challenge

> Stonepass doesn't close for weather anymore. It closes on words borrowed from weather — "raiders," "avalanches," "public order" — while the schedule underneath keeps quietly playing favourites [...] Elric first needs the number nobody at the gate wants published: the least total time this exact column of convoys could possibly spend waiting, under any legal assignment of clearances to convoys.

Stripped of the flavour text, the specification is:

- Each convoy has a known **arrival time**.
- Each clearance has a known **opening time** and seats **exactly one** convoy.
- A clearance may only seat a convoy whose arrival time is **at or before** the clearance opens.
- Minimise the **total wait**, summed over the whole column.

A single Docker endpoint was provided.

---

## Step 1: A wrong turn worth recording

The endpoint looked like a classic interactive pwn/misc target, so my first instinct was a socket client — connect, parse the prompt, reply with the answer, loop until a flag appears.

That model was wrong, and the way it failed is the useful part:

```
Test case 1 failed - Wrong answer
Input:
5 8 31 134 12 174 131 153 38 37 150 142 136 15 178
Output:
Toll Schedule - minimum total convoy wait. Usage: python toll_schedule.py ...
Expected:
26
```

The "output" being my own `--help` text is the tell. The script had been invoked with **no arguments**, fell through its argv dispatch, and printed its docstring. Which means the target isn't a service that talks to my client — it's a **judge**. It takes source code, pipes a test case into `stdin`, and diffs `stdout`.

**Lesson:** if a judge echoes your usage banner back as your submission's output, you've misread the interaction model. Stop writing networking code.

That failure also handed over a labelled sample — input *and* expected answer — which is exactly what's needed to nail the input format.

---

## Step 2: Recovering the input format

The sample is fifteen integers:

```
5 8 31 134 12 174 131 153 38 37 150 142 136 15 178
```

First guess: leading `n = 5`, then 5 arrivals, then a count, then that many clearances. That gives `5 | 8 31 134 12 174 | 131 ...` — but then the next count would be `131` with only 8 integers remaining. Dead.

Second guess: the first **two** values are both counts.

- `n = 5` convoys, `m = 8` clearances
- arrivals: `31 134 12 174 131`
- clearances: `153 38 37 150 142 136 15 178`

Arithmetic checks: `2 + 5 + 8 = 15`. ✅

Confirmed against the expected answer of 26 (derivation below). Because the judge may split this across one line or four, the parser should be whitespace-agnostic — `sys.stdin.read().split()` rather than line-by-line reads.

---

## Step 3: The observation that collapses the problem

The wording pushes you toward min-cost bipartite matching — n convoys, m clearances, edge costs, Hungarian algorithm, `O(n³)`. Resist that.

Total wait for any assignment is:

```
Σ (clearance_time − arrival_time)  =  Σ chosen clearances  −  Σ served arrivals
```

When `m ≥ n`, **every convoy is seated**, so `Σ served arrivals` is a constant — it doesn't depend on the assignment at all.

So the cost function doesn't care *which convoy goes to which clearance*. It only cares **which clearances you open**. The matching problem is really a **selection** problem:

> Choose the `n` cheapest clearances such that a legal assignment still exists.

This is what the flag is pointing at. The pairing is a red herring; the schedule's power lives entirely in which slots stay shut.

---

## Step 4: When is a selection legal?

Sort arrivals ascending as `a₁ ≤ … ≤ aₙ`, and the chosen clearances ascending as `c₁ ≤ … ≤ cₙ`. A legal assignment exists **iff**:

```
c_k ≥ a_k    for every k
```

This is Hall's condition specialised to an interval structure. Intuition: matching the k-th earliest convoy to the k-th earliest chosen clearance is optimal-feasible — if *any* legal assignment exists, the sorted pairing is legal, because sorting only ever relaxes constraints.

Equivalent phrasing that's easier to reason about greedily: for every threshold `x`, the number of chosen clearances `≥ x` must be at least the number of convoys arriving `≥ x`.

---

## Step 5: The greedy

Walk convoys from **latest arrival to earliest**. Maintain a min-heap of clearances currently eligible.

```
sort arrivals descending
sort clearances descending
for each arrival x (latest first):
    push every not-yet-pushed clearance ≥ x into the min-heap
    pop the minimum → that's the clearance we open
```

Because clearances are consumed in descending arrival order, the pool of eligible clearances only ever **grows**, so a simple two-pointer sweep feeds the heap.

### Why it's correct

Let `a_max` be the latest arrival and let `c*` be the globally smallest clearance `≥ a_max`. Claim: some optimal selection contains `c*`.

Take any optimal selection `S`. It must contain at least one clearance `≥ a_max` (something has to seat that convoy); let `c'` be the smallest such. By definition of `c*`, we have `c* ≤ c'`.

Consider `S' = S − {c'} + {c*}`. The cost does not increase, since `c* ≤ c'`.

Feasibility survives too. Lowering an element in a sorted multiset shifts every element in the range `[c*, c')` one index to the right, where each faces a *stricter* requirement. But every such element is `≥ c* ≥ a_max`, and `a_max` is the largest arrival — so those elements clear **any** constraint regardless of where they land. `c*` itself is likewise `≥ a_max`. So `S'` is legal and no worse than `S`.

Fix that choice, delete the convoy and the clearance, induct on what's left. The heap implementation performs exactly this induction.

**Complexity:** `O((n + m) log m)`.

---

## Step 6: The mirror case

If `m < n`, the situation inverts: every clearance gets used, and you choose *which convoys to serve*. Now `Σ chosen clearances` is the constant, and cost `= Σ clearances − Σ served arrivals`, so you **maximise** the arrival sum.

Symmetric greedy: walk clearances ascending, push every arrival `≤` the current clearance into a **max**-heap, pop the latest.

The judge may never test this branch, but it's four lines and removes a whole class of surprise.

---

## Step 7: Verifying before submitting

Never trust a greedy on vibes. I brute-forced every permutation on small random instances and diffed:

```python
def brute(arrivals, slots):
    n, m = len(arrivals), len(slots)
    best = None
    for perm in itertools.permutations(range(m), n):
        if all(slots[perm[i]] >= arrivals[i] for i in range(n)):
            c = sum(slots[perm[i]] - arrivals[i] for i in range(n))
            best = c if best is None else min(best, c)
    return best
```

Results:

- **545/545** feasible random cases matched brute force exactly (infeasible ones excluded).
- Sample case returns **26**. ✅
- 200 000 convoys × 200 000 clearances: **0.27 s**.

Tracing the sample by hand:

| convoy | clearance | wait |
|-------:|----------:|-----:|
| 174 | 178 | 4 |
| 134 | 136 | 2 |
| 131 | 142 | 11 |
| 31 | 37 | 6 |
| 12 | 15 | 3 |
| | **total** | **26** |

Note which clearances are never opened: **38, 150, 153**. That surplus is the entire challenge. With `m = n` the answer would be forced (`Σ clearances − Σ arrivals`) and there'd be nothing to solve.

---

## Step 8: Final solution

```python
import sys
import heapq


def main():
    nums = list(map(int, sys.stdin.read().split()))
    if not nums:
        return

    n, m = nums[0], nums[1]
    arrivals = nums[2:2 + n]
    slots = nums[2 + n:2 + n + m]

    if m >= n:
        # Every convoy is seated, so the arrival sum is fixed and the job is
        # to open the n cheapest clearances that still admit a legal matching.
        a = sorted(arrivals, reverse=True)
        s = sorted(slots, reverse=True)
        heap, idx, chosen = [], 0, 0
        for x in a:                        # latest convoy first = most constrained
            while idx < m and s[idx] >= x:
                heapq.heappush(heap, s[idx])
                idx += 1
            if not heap:                   # no clearance opens late enough
                print(-1)
                return
            chosen += heapq.heappop(heap)  # cheapest clearance it can legally take
        print(chosen - sum(arrivals))
    else:
        # Every clearance is used, so maximise the arrivals actually served.
        a = sorted(arrivals)
        s = sorted(slots)
        heap, idx, total = [], 0, 0
        for t in s:
            while idx < n and a[idx] <= t:
                heapq.heappush(heap, -a[idx])
                idx += 1
            if not heap:
                print(-1)
                return
            total += t + heapq.heappop(heap)
        print(total)


if __name__ == "__main__":
    main()
```

The `print(-1)` guards handle an unservable convoy. The expected output for an infeasible case is unspecified, but an empty `stdout` from an uncaught `IndexError` is a guaranteed fail, so the guard is free insurance.

---

## Flag

```
HTB{th3_p4ss_pr3f3rs_0n3_b4nn3r}
```

---

## Takeaways

1. **Identify the interaction model first.** A judge and an interactive service look identical from a port number. Getting your own usage text back as "your output" is the diagnostic.
2. **A failing test case is free intel.** The rejection handed over both a sample input and its expected answer — enough to pin down an undocumented format.
3. **Check whether the cost function is actually constant in the thing you're optimising.** Recognising that `Σ arrivals` is fixed turns `O(n³)` min-cost matching into an `O(n log n)` selection.
4. **Brute-force your greedy on small inputs.** Exchange arguments are easy to believe and easy to get wrong; a few hundred randomized diffs cost about a minute.
