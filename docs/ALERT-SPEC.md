# Alert Specification — Three CV Alerts (Phase 2)

**Date:** 2026-06-18 · **Audience:** OT security & operations teams (and the grading panel).
Every alert below is implemented as a **pure detection function** in `app/alerts/` that takes
parsed CV data in and returns `Alert` objects out (no network calls), and is unit-tested in
`tests/`. Counts and examples are from the **real** Center data (180 assets, 300 activities,
45 assets with CVEs). Reproduce with `python scripts/run_alerts_offline.py`.

The `Alert` object follows the contract in `.claude/skills/alert-design`:
`id, category, title, severity, status, detected_at, assets[], evidence{}, rationale,
compliance_ref, recommended_action` (+ optional `score`). See `app/models.py`.

---

## ⚠️ Global caveat — this is a STATIC capture, not a live feed

This Center holds **imported PCAPs** (see `docs/API-FINDINGS.md`). There is no live clock:
every timestamp sits inside one capture window (~7 minutes wide). So:

- **`reference_now` = the newest `lastActivity` in the dataset**, not wall-clock now
  (policy key `reference_now_strategy: max_last_activity`). All time math is relative to that.
- Time-based detection (the silence alert) is designed so the **logic is identical on a live
  feed** — only the clock source changes. On a live deployment you would poll on an interval
  and `reference_now` becomes the poll time.
- CV's own **events, baselines, and groups are empty/absent** on this instance, so we do not
  ride on native CV alarms — we compute everything ourselves and **author the expected state**
  (`app/policy/expected_state_policy.yaml`).

---

## 1. Operations — "Asset went silent"  (`app/alerts/operations.py`)

Maps to the assignment's *"sudden stop of device communication."*

**Trigger logic.** A naive "no traffic for N seconds vs the capture end" flags ~all 180 assets,
because whole capture cells stop together at the end of their PCAP. Instead we detect an asset
that fell silent **while its peers kept talking**: group assets by `/24` subnet (an OT cell),
take the cell's **median** `lastActivity`, and fire when an asset's own `lastActivity` is more
than `min_seconds_behind_zone_median` (default **60 s**) behind that median. A cell that stopped
all at once moves its median with it, so it is *not* flagged — only genuine stragglers are.
Zones with `< 3` assets are skipped (too few peers to define "normal").

**Exact CV fields used:** `components[].lastActivity` (epoch ms), `components[].ip` (→ `/24`
zone), `components[].mac` (disambiguates components sharing an IP), `components[].tags[]`
(Purdue level + `Controller`/`PLC` for the severity bump).

**Severity rule (derived, see `_severity`):** by lag magnitude — `≥180 s → high`,
`≥120 s → medium`, else `low`; **+1 level if the asset is a controller** (operationally
critical). So a silent controller ≥180 s behind → `critical`.

**Evidence captured:** subnet, zone peer count, asset `last_seen` (ISO), `zone_median_last_seen`,
`seconds_behind_zone_median`, `is_controller`, `purdue_level`.

**OT rationale:** a device going quiet while peers continue can mean a failed controller/sensor,
a pulled cable, or an attacker silencing a device — each interrupts the physical process.

**Compliance:** NIST SP 800-82r3 (continuous OT monitoring); NERC CIP-007 (security event monitoring).

**Recommended action:** verify power/reachability; if a controller, check process state; raise an
ops ticket and inspect the switch port/link if the silence is unexpected.

**Real result:** **5 fired** (high=4, low=1). Top: `192.168.40.10 [84:8a:8d:c3:ff:03]` 227 s behind
its cell; several interfaces under `172.26.16.10` ~185–223 s behind. (Note: the *named Rockwell
controllers* at those IPs stayed fresh — it's auxiliary interfaces that went quiet.)

---

## 2. Security — "Unexpected / unauthorized communication"  (`app/alerts/security.py`)

Maps to the assignment's *"unexpected asset connecting."* Reads the authored policy
(`app/policy/expected_state_policy.yaml`) — **this file is the alert's brain**; retune without
code changes. Broadcast/multicast endpoints (`x.x.x.255`, `224.0.0.0/4`) are ignored as non-assets.

**Trigger logic — four rules:**

| Rule | Fires when | Grouped by | Severity |
|---|---|---|---|
| **SKIP_LEVEL** | two endpoints are non-adjacent Purdue levels (pair not in `allowed_level_adjacencies`) | the supervisory (higher) host | `critical` if level gap ≥ 2, else `high` |
| **INSECURE_PROTOCOL** | a controller exchanges a cleartext (`HTTP/Telnet/FTP/TFTP`) or IT (`SMB/NetBIOS/DCE-RPC`) protocol | the controller | cleartext → `high`; IT → `medium` |
| **EXTERNAL_COMMS** | an endpoint IP is outside every `ot_networks` range | the external IP | `high` |
| **UNKNOWN_VENDOR** | a controller talks to an asset whose vendor is not on `known_vendors` | controller+vendor | `medium` |

Grouping means a host bypassing the conduit to many field devices is **one actionable alert**,
not dozens of near-duplicates.

**Exact CV fields used:** activity `left`/`right` `tags[]` (Purdue level via `category.label`
"Device - Level …", vendor via `category.label == "System"`, `Controller`/`PLC` tag),
`left/right.ip[]`, activity `tags[]` with `category.label == "Protocol"` (the protocol set),
`lastActivity`.

**Evidence captured:** `rule`, supervisory host / controller identity, field-peer or peer list
with IP+level, `peer_count`, `level_gap`, `protocols`.

**OT rationale:** the Purdue model (IEC 62443 / NIST 800-82) requires traffic to cross adjacent
zones through a conduit. A site/IT host reaching field devices directly is a segmentation breach
and a lateral-movement path toward the physical process; cleartext/IT protocols on control assets
leak credentials/commands.

**Compliance:** NIST SP 800-82r3 (zones & conduits); IEC 62443; NERC CIP-005 (electronic security
perimeter); NIS2 (risk-management measures) for the protocol rule.

**Recommended action:** confirm whether the path is sanctioned; if not, block at the cell/zone
firewall and route through the Level-2 conduit; disable/tunnel insecure protocols; restrict
management to a hardened jump host.

**Real result:** **18 fired** (critical=4, high=3, medium=11). Headline: Level 3-4 hosts
`192.168.{40,50,30,20}.3` each reach **3–5 field devices directly**, skipping Level 2. Cleartext
HTTP on inspection/cooling hubs (high); Windows SMB/NetBIOS on HMI/control stations (medium).
> Tuning knob: the medium "IT-protocol-on-HMI" tier can be silenced by emptying
> `insecure_protocols.it_in_ot` in the policy if a site considers SMB on HMIs acceptable.

---

## 3. Free-choice — "Vulnerable asset exposure"  (`app/alerts/custom.py`)

**Why this one (decision + tradeoff):** the per-component CVE data is the richest, best-grounded
dataset here. But a raw "has a CVE" alert is useless — **all 45 vulnerable assets are CVSS ≥ 9**.
The real product question is *"which vulnerable assets do I patch first?"* So this is a risk
**prioritization** alert, combining severity, reachability, and operational criticality.

**Trigger logic / score (documented rule, see `exposure_score`):**
```
score = max_cvss*4  +  min(cve_count,50)*0.6  +  (15 if communicating else 0)  +  (10 if controller else 0)
```
Fires only at/above `min_score` (default **80** → high/critical band). `communicating` is decided
by joining the asset's **IP/MAC** to the activity graph — **not** by id, because the comms graph
uses a different id space than `/components` (matching on id returns nothing — a real trap found
during discovery).

**Exact CV fields used:** `components/{id}/vulnerabilities[].CVSS`, `.cve`, `.title`,
`.CVSSVersion`; `components[].vulnerabilitiesCount`; the asset's `ip`/`mac` vs the activity graph;
`Controller`/`Level 2` tag.

**Severity rule (tightened gate, `_severity`):** `critical` **only if** `max_cvss ≥ 9` **AND**
the asset is **cross-zone reachable** (participates in an activity spanning two Purdue levels)
**AND** it is **control-plane** (a controller or Purdue Level ≤ 2). Any other firing alert is
`high` (the `medium`/`low` bands apply only if `min_score` is lowered). The gate is deliberately
narrow so "critical" means *severely vulnerable AND on the control plane AND exposed across zones*
— the real top-priority condition, not just a high score.

**Evidence captured:** `exposure_score` + full `score_breakdown`, `cve_count`, `max_cvss`,
`communicating`, `is_controller`, `purdue_level`, and the **top 5 CVEs** (id, CVSS, title).

**OT rationale:** vulnerable + reachable + process-critical = remediate first; an exploit here can
directly disrupt operations.

**Compliance:** NERC CIP-007 (patch & vulnerability management); NIST SP 800-82r3 (risk-based remediation).

**Recommended action:** prioritise patching/mitigation; if patching is impossible, isolate behind a
cell firewall and restrict exposed protocols/ports.

**Real result:** **15 fired** (critical=12, high=3). The critical set is dominated by the
**Cisco IE3400 / IE9300 industrial switches — i.e. the network infrastructure itself is the
single highest-exposure asset class on this OT network** (CVSS 10, 40–80 CVEs each, Level-2,
cross-zone). The 3 `high` are the same kind of Level-2 switch but not cross-zone in this capture,
which is exactly what the tightened gate is meant to separate.

---

## Assumptions (stated explicitly)

1. **Static snapshot.** Timestamps live inside one capture; `reference_now = max(lastActivity)`.
   The logic ports to live polling unchanged.
2. **`/24` ≈ an OT cell.** Used for the silence "peer group" and as the OT zone unit. Derived from
   the 8 real subnets observed; refine to true VLAN/zone maps if available.
3. **Purdue level comes from CV tags** (`Device - Level 0-1 / 2 / 3-4`). 51 assets are untagged
   ("unknown"); they are excluded from the level-based rules (never the basis of a violation alone).
4. **Authored baseline.** Allowed adjacencies, OT subnets, known vendors, and insecure-protocol
   lists are our policy (CV has no baseline here). They are grounded in the real inventory but are
   a *starting* policy a site would review.
5. **SNMP is intentionally allowed** to managed cell switches (else it floods the alert); re-enable
   per-site if SNMPv1/v2c is disallowed.
6. **"Controller"** = CV `PLC`/`Controller` tag or Purdue Level 2. Cisco IE industrial switches
   carry Level-2 tags and are therefore treated as control-plane assets.
7. **CVE↔asset join is by IP/MAC**, because the comms-graph id space differs from `/components`.
