# Creativity — Optional Improvements, Why, and Tradeoffs

The brief asks what optional improvements we chose, why, and the tradeoffs. Below are the deliberate
creative choices already built into the submission, then an honest list of what we'd do next and why
it was out of scope for a 2–3 day budget.

## What we chose to build (and why)

### 1. Exposure-fusion custom alert (CVE × communication-graph reachability)
The easy "free-choice" alert is "this asset has a critical CVE." On this data that's noise — all 45
vulnerable assets are CVSS ≥ 9, so it ranks nothing. We instead **fused two datasets** into a single
prioritization score: vulnerability severity and breadth *crossed with* whether the asset is actually
**communicating** and whether it sits on the **control plane**. The creative leap is treating "exposure"
as a property of the asset *in its network context*, not of the CVE in isolation — which is how an OT
team actually triages. **Tradeoff:** the score's weights are a defensible judgment, not an industry
standard; they're centralized in one function so they can be tuned, and the gated critical band keeps
the top tier meaningful.

### 2. Alert → graph "blast radius" highlight
Selecting any alert highlights **exactly** the assets and conversations it implicates on the Purdue-
layered topology and dims everything else. This turns the comms graph from a static picture into an
investigation tool: *what does this alert actually touch, and what could it reach?* Making it work
uniformly across all three alert types required the IP/MAC cross-id-space landing (see
`ENGINEERING-NOTES.md`). **Tradeoff:** with broadly-connected assets the highlighted set can be large;
we cap zoom and dim aggressively so the focus still reads.

### 3. Snapshot / live safety toggle (`DATA_MODE`)
A single env var flips the backend between a **public-safe frozen snapshot** (never calls the Center,
needs no token) and a **gated live** proxy. This is creativity in the *product-safety* sense: it let us
ship a genuinely public demo URL without publishing live OT telemetry or standing a credential up on an
open host — while the `data_source` badge keeps the UI honest about which one is serving. **Tradeoff:**
the public URL demonstrates the UI and the (real) alert outputs but not a live Center connection; that
path is exercised locally and documented.

### 4. Resilience fallback + cold-start UX
If a live Center call fails, the backend degrades to the snapshot instead of erroring, and every
response says which source served it. The frontend has first-class loading / empty / error states and a
Render cold-start **"waking up…"** state with backoff, so a reviewer's first hit on a sleeping free-tier
instance reads as "starting," not "broken." **Tradeoff:** a fallback could in principle mask a real
outage — mitigated by surfacing `data_source` prominently rather than hiding the switch.

## What we'd do next (and why it was out of scope)

- **Streaming for true real-time.** Today the model is poll-based snapshots, which matches the exercise
  and the imported-PCAP dataset. Real-time silence/intrusion detection wants a push pipeline
  (CV syslog/MQTT/webhook → event store → WebSocket to the UI). Out of scope because it's a different
  architecture and the sandbox data isn't a live stream — but the detectors were written to port
  unchanged to a live clock.
- **Configurable thresholds UI.** The silence window, exposure weights, and the expected-state policy
  are file/parameter-driven today. A small in-app settings panel (with per-zone overrides) would let an
  analyst tune false-positive vs. missed-detection without editing YAML. Deferred as polish once the
  detection logic was proven.
- **Alert acknowledgement / triage workflow.** Alerts are currently stateless (`status` exists in the
  model but isn't persisted). A real console needs ack/assign/resolve with an audit trail and a small
  datastore. Deferred because it adds persistence and auth scope beyond the core "detect + visualize"
  ask — though the CV vulnerability data already carries an ack field we could build on.
- **Historical trend over time.** The Trends view summarizes the current snapshot; a time-series of
  alert volume/severity would need stored poll history. Deferred with the same persistence tradeoff.

The throughline: we spent the budget making the **core three alerts correct, grounded, and
explainable**, and the visualization genuinely useful, rather than spreading thin across half-built
extras. Each item above is a real next step, not a missing requirement.
