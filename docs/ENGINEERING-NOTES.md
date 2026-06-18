# Engineering Notes — Non-obvious Problems Solved

A record of the real problems that came up while building this, and how they were solved. These are
the things you only hit by actually connecting to the data and running the code — they're here so it's
clear this was *engineered*, not just generated.

---

## 1. "Device went silent" floods on a static capture — the subnet-median baseline

**The trap.** The obvious silence rule is: `now − last_seen > threshold`, where `now` is the newest
timestamp in the dataset. On this Center that flags **173 of 180 assets**. The data is imported PCAPs
(`cluster01-merged.pcap`, …), so timestamps cluster by capture file: when a file ends, *every* asset
in it goes "silent" at once. An absolute threshold therefore mostly encodes *which PCAP an asset came
from*, not whether it actually failed.

**The fix.** Detect an asset that fell silent **while its peers kept talking.** Group assets by `/24`
subnet (an OT cell), take the cell's **median** `last_seen`, and flag only assets more than a
threshold behind that median. A cell that stops as a unit drags its own median down with it, so it
isn't flagged; only true stragglers are. On the real data this collapses 173 false positives to **5
genuine stragglers.** The detection logic is unchanged for a live feed — only the definition of "now"
moves from `max(last_seen)` to wall-clock poll time.

*(See `app/alerts/operations.py`; the distribution analysis that drove the threshold is summarized in
`ALERT-SPEC.md`.)*

---

## 2. CVE↔asset join returns zero — the dual id-space discovered by IP/MAC

**The trap.** To prioritize *communicating* vulnerable assets, you join the vulnerable components
(from `/components`) against the communication graph (from `/activities`). The natural key is the
component `id`. **It returns nothing.** Cyber Vision's activity/visualisation endpoints use a
**different id space** than `/components` — the same physical asset has one id in the inventory and a
different id as a graph endpoint. Matching on `id` silently yields an empty set, which would have
quietly made the custom alert report "0 communicating" and looked *correct*.

**The fix.** Join on **IP and MAC**, which are stable across both id spaces. `communicating_keys()`
and `cross_zone_keys()` build IP/MAC sets from the graph; the custom detector intersects the asset's
IPs/MACs against them. This is the difference between the alert firing on the right 15 assets versus
firing on none. It's also a good reminder to verify a join actually matches rows rather than trusting
that two endpoints "obviously" share a key.

*(See `app/alerts/custom.py`.)*

---

## 3. Landing alerts on the graph across both id-spaces — `/graph` highlight

**The problem.** The graph nodes come from `/activities` (graph id-space). But operations and custom
alerts carry *component* assets (inventory id-space), while security alerts carry *activity* assets.
If the UI matched alerts to nodes by id, operations/custom highlights would land on nothing.

**The fix.** `app/graph.py` stamps every node and edge with the ids of the alerts that implicate it,
resolved by **IP/MAC overlap** rather than id — so a component-space alert and an activity-space alert
both light up the same physical node. The frontend then highlights exactly the elements whose
`alert_ids` include the selected alert and dims the rest. This is what makes the "blast radius"
interaction work uniformly for all three alert types.

---

## 4. The communication graph collapsed to a single point — React strict-mode + lazy mount

**The symptom.** In the deployed-style build the Cytoscape graph rendered all 120 nodes piled on top
of each other at the origin (bounding box ~94×50 px) instead of a spread topology. No console error.

**The diagnosis (two compounding bugs).**
1. **Zero-size layout.** The graph tab mounts lazily; if `fcose` runs before the container has real
   height, every node is laid out into a 0×0 box and collapses to (0,0). Confirmed by probing node
   positions: container was 1558×671 but all nodes sat at (0,0).
2. **React strict-mode double-mount.** In dev, React mounts → unmounts → remounts. The unmount
   *destroyed* the first Cytoscape instance, and the second instance skipped layout because the
   "structure changed" guard (a signature ref) had already been set by the first. So the real, visible
   instance was never laid out. Proven by running `fcose` manually from the page console — it spread
   the nodes fine (1078×845), so the extension worked; the *invocation path* was the bug.

**The fix.** (a) Lay out whenever a fresh Cytoscape instance is created, not only when the topology
signature changes — so the strict-mode second instance gets laid out. (b) Defer the layout via
`requestAnimationFrame` until the container actually has non-trivial size, retrying for a few frames.
(c) Add a `ResizeObserver` so the canvas stays correct when the window/panel resizes, and cap
`maxZoom` so highlighting a 2-node alert doesn't zoom to an unreadable extreme. After the fix the
bounding box is ~1083×1127 and the topology reads as intended.

*(See `app/.../components/GraphCanvas.tsx` in the frontend repo.)*

---

## 5. Smaller but real

- **Self-signed TLS on a raw IP.** `httpx(verify=False)` is isolated to the single `cv_client.py`
  factory with an "exercise-only" comment, never sprinkled across the code.
- **No pagination metadata.** The Center returns no `X-Total-Count`; totals are obtained by requesting
  a large page and counting — documented so it isn't mistaken for a guess.
- **Python 3.14 wheels.** `pydantic-core` 2.9 had no 3.14 wheel and failed to build from source;
  pinned to a version (2.13.4) that ships a `cp314` wheel.
- **Windows console encoding.** The CLI runner reconfigures stdout to UTF-8 so the `↔` in alert titles
  doesn't crash on cp1252.
