# Design Choices & Intended Audience

## Who this is for

The primary user is an **OT SOC analyst or plant security engineer** sitting in front of an
industrial network they are responsible for keeping both *safe* and *running*. That dual mandate
shapes everything. Unlike an IT analyst, this person cannot simply quarantine a suspicious host —
isolating the wrong PLC can stop a production line or trip a safety system. So they don't just need
to know *that* something is wrong; they need to know **which asset, in which Purdue zone, how bad,
why it matters, and what to do about it** — fast enough to act before a shift changes or a process
drifts. The dashboard is built for that triage loop: a severity-ranked alert list, one click to the
full evidence and a recommended action, and a topology view that shows the *blast radius* of any
alert. Scannability and trust beat visual flash.

The secondary audience is the **Cisco interview panel**. They are reading this to judge product
thinking, engineering practice, and how decisions are made under ambiguity. So the same artifacts
that serve the analyst (clear evidence, documented rationale, honest limitations) double as the
argument that this was *reasoned about*, not just assembled.

## The backend-proxy architecture, and why it is non-negotiable

The browser **never** talks to the Cyber Vision Center. Every request goes
`browser → our FastAPI backend → Center`, and the CV API token lives only on the server (in a local
`.env` or the host's secret store, never in git, never in a client bundle). For a *security* product
this is not a nicety — shipping an OT credential to every visitor's browser would be a disqualifying
flaw, the kind of thing this very dashboard is meant to catch. Keeping the token server-side is the
first design choice and the one we would defend hardest.

The proxy earns its place three more ways: it **normalizes** messy, inconsistent CV payloads into
clean typed models (a component's `ip` is a string; an activity endpoint's `ip` is an array — the
client should never see that seam); it runs the **alert engine** server-side over cached data so the
detection logic is testable and the browser stays a thin renderer; and it **shields the Center** with
a TTL cache so a slow, rate-limited OT appliance is never hit on every page poll.

## The three alerts, and the reasoning behind each

We deliberately chose one alert per axis of OT risk — *availability*, *intrusion*, and *latent
exposure* — so the set tells a complete story rather than three variations on one theme.

**Operations — "asset went silent."** The assignment's own example. The naïve implementation
(no traffic for *N* seconds versus the capture's end) flags ~all 180 assets here, because this is an
imported-PCAP dataset where whole capture cells stop together at the end of their file. That would be
worse than useless — an alert that fires on everything trains analysts to ignore it. So "silent" is
defined **relative to the asset's own subnet (cell): it went quiet while its peers kept talking.**
A cell that stops as a unit moves its own median and is *not* flagged; only genuine stragglers are.
The detection logic is identical on a live feed — only the clock source changes.

**Security — "unexpected / unauthorized communication."** The assignment's other example
("an unexpected asset connecting") and the most consequential decision in the project. Cyber Vision
*can* learn a baseline and raise its own deviation events — but on this instance the `events`,
`baselines`, and `groups` endpoints are all **empty or absent** (documented in `API-FINDINGS.md`).
We could have shrugged and said "no baseline, no alert." Instead we **translated the ambiguity into an
explicit, authored expected-state policy** (`app/policy/expected_state_policy.yaml`): the allowed
Purdue-level adjacencies, the real OT subnets, a known-vendor allowlist, and the cleartext/IT
protocols that have no business on a controller — every value derived from the actual inventory. The
detector flags violations of *that* policy: a field device reaching a site/IT host directly (skipping
the control layer), cleartext protocols on a controller, external conversations. Making the baseline a
**documented file an operator can edit** is the product decision: the "expected state" of an OT network
is a human judgment, so we surfaced it as policy-as-data rather than burying assumptions in code.

**Free choice — "vulnerable asset exposure."** We picked this because the per-component CVE data is
the richest, best-grounded dataset on this Center — and because a naïve version is a trap worth
showing we avoided. *Every* one of the 45 vulnerable assets scores CVSS ≥ 9, so "has a critical CVE"
ranks nothing. The real question an OT team asks is **"what do I patch first?"** So this is a
risk-*prioritization* alert: an exposure score that fuses vulnerability severity, breadth (CVE count),
**reachability** (is the asset actually on the comms graph?), and **operational criticality** (is it on
the control plane?). It is the one alert that consumes the other two's data — inventory *and* the
communication graph — which is exactly the synthesis a good triage tool should perform.

## The severity model

Severity is **rule-derived and written down**, never hand-assigned (see `ALERT-SPEC.md` for the exact
rules). Operations severity rises with how far an asset has fallen behind its peers and is bumped a
level if it's a controller. Security severity is set per rule, with a skip-of-two-Purdue-levels rated
critical. The custom alert's **critical band is deliberately gated**, not just a high score: an asset
is critical only if it is *severely vulnerable (CVSS ≥ 9) AND cross-zone reachable AND on the control
plane*. The gate exists because "critical" is a word that should mean *drop what you're doing* — so we
made it hard to earn. On the real data this cleanly separates the Cisco IE3400/IE9300 switches (the
network infrastructure itself, the single highest-exposure class) from merely-vulnerable Level-2 gear.

## Public snapshot vs. gated live — a security decision, not a limitation

The deployed public demo runs in **snapshot mode**: it serves a frozen, bundled copy of the dataset
and **never opens a connection to the Center**. This is a deliberate exercise of the same OT security
judgment the product embodies. Continuously exposing a real industrial network's live asset, flow, and
vulnerability data on an open URL is precisely the kind of leak an OT tool should *prevent*; a public
endpoint also invites crawler traffic we must not relay onto a slow, rate-limited Center; and a public
host should hold no credential at all. So the public URL is intentionally a static-data demonstration,
while **`DATA_MODE=live`** (token required, server-side) runs the full proxy against the Center for
real use. Crucially, the `data_source` badge on the dashboard **always tells the truth** — "Snapshot"
on the demo, "Live" otherwise — because a security tool that misrepresents its own data provenance has
already failed. We treat this not as a corner we cut but as the correct call for a security product
shipped to a public URL.
