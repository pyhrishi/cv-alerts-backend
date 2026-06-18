# API Findings — Cyber Vision Center (Phase 1 Discovery)

**Date:** 2026-06-18
**Center:** `https://52.58.209.184` (AWS EC2, self-signed TLS — we call it with cert
verification OFF, isolated to one client and flagged exercise-only).
**Audience:** the PM (you). Plain-language map of what the live API actually returns and
which of the three planned alerts the real data can support.

> How this was produced: three read-only discovery scripts
> ([scripts/discover.py](../cv-alerts-backend/scripts/discover.py),
> [discover2.py](../cv-alerts-backend/scripts/discover2.py),
> [discover3.py](../cv-alerts-backend/scripts/discover3.py)) hit the live Center with
> GET requests only and saved trimmed real samples to [docs/api-samples/](api-samples/).
> The token is loaded from `.env` and never printed or saved.

---

## 1. Authentication — CONFIRMED ✅

| Item | Value |
|---|---|
| Auth header | **`x-token-id: <token>`** (the skill's "likely" guess was correct; alternatives `Authorization: Bearer`, `x-api-key` all 404/fail) |
| API version path | **`/api/3.0`** (tried 3.1 / 2.0 / 1.0 — only 3.0 responds) |
| Confirming endpoint | `GET /api/3.0/version` → `200` |
| TLS | self-signed; `verify=False` (exercise-only, isolated in the client factory) |

There is **no machine-readable OpenAPI/Swagger spec** exposed (tried 9 common paths, all
404). The API docs at `/#/admin/api/documentation` are a browser-only single-page app, so
endpoint names below were confirmed empirically by probing, not read from a spec.

---

## 2. The data model in one paragraph

This Center holds **imported PCAP captures** (presets are named `cluster01-merged.pcap`,
etc.), not a live sniffing feed. Everything is organized around **presets** = saved filtered
views. Two presets matter to us: **"All data"** (`d5af074a-…`) and **"All Controllers"**
(`ad6bfa43-…`). The network inventory is **components** (assets); who-talks-to-whom is
**activities** (aggregated component↔component links — this is our comms graph); risk is
**vulnerabilities** (CVEs, both a global catalog and per-component matches).

---

## 3. Working endpoints

| Endpoint | Status | Count (live) | One-line description |
|---|---|---|---|
| `GET /api/3.0/version` | 200 | — | Auth smoke test / API version. |
| `GET /api/3.0/components` | 200 | **180** | The asset inventory. Identity + counts per device. |
| `GET /api/3.0/components/{id}/vulnerabilities` | 200 | (9 on sample) | **Per-asset CVE list** with CVSS + ack workflow. |
| `GET /api/3.0/activities` | 200 | **350** | **Comms graph edges** (component↔component, with protocols). |
| `GET /api/3.0/presets/{id}/visualisations/activity-list` | 200 | 300 (All data) | Same edges, scoped to a preset. Richest comms source. |
| `GET /api/3.0/presets/{id}/visualisations/component-list` | 200 | 180 (All data) | Inventory scoped to a preset. |
| `GET /api/3.0/vulnerabilities` | 200 | **3515** | Global CVE knowledge base (catalog, not asset-linked). |
| `GET /api/3.0/presets` | 200 | 36 | Saved views (zones/filters). Holds the preset IDs above. |
| `GET /api/3.0/sensors` | 200 | 9 | Capture points (one per imported PCAP cluster). |
| `GET /api/3.0/tags` | 200 | 442 | Tag dictionary: protocols, vendors, **Purdue levels**. |

### Not available / empty (important caveats)

| Endpoint | Result | Consequence |
|---|---|---|
| `GET /api/3.0/flows` | 200 but **0 items** | Raw packet-flow layer isn't retained for these imports. **Use `activities` instead** — it's the aggregated layer and is fully populated. |
| `GET /api/3.0/events` | **404** | No events endpoint in 3.0. CV's pre-computed events/alarms are **not** available to us — we compute our own alerts. |
| `GET /api/3.0/baselines` | 200 but **0 items** | No baselines configured. We **cannot** lean on CV's native "deviation from baseline." We must declare our own expected-state policy for the security alert. |
| `GET /api/3.0/groups` | 200 but **0 items** | No custom asset groups defined. Zoning must come from **tags** (Purdue levels) instead. |

### Pagination & limits
- Paging via `?page=&size=` query params. There is **no `X-Total-Count` header**; to get a
  total you request a large `size` and count the array. Counts above were taken that way.
- No rate-limiting or auth errors observed during discovery. One transient `503` on a
  single preset's activity-list (retry succeeded) — the Center is occasionally slow, which
  **justifies the TTL cache** in our backend.

---

## 4. Field map — what each endpoint gives us

**components** (`docs/api-samples/components.json`)
- Identity: `id`, `label`, `ip`, `mac`, `device.*`, vendor via `normalizedProperties`
  (`vendor-name`, e.g. "Siemens AG", "Rockwell Automation"), `public-ip: yes/no`.
- **Timestamps (epoch ms):** `firstActivity`, `lastActivity` — first/last time the asset was
  seen. Core input for the "silent device" alert.
- Risk/relations: `vulnerabilitiesCount`, `eventsCount`, `externalCommunicationsCount`,
  `flowsCount`, `requestsCount`.
- **Zone identity:** `tags[]` with `category.label` like **"Device - Level 0-1"**,
  **"Device - Level 2"** → the **Purdue model level**. Also vendor/system tags.

**activities** (`docs/api-samples/activities.json`, `activities_alldata.json`) — the comms graph
- `left` and `right` = the two endpoints, each with `id`, `label`, `ip[]`, `mac[]`, `tags[]`
  (Purdue level + vendor), `icon`.
- `tags[]` at the activity level = **protocols** (`ARP`, `CIP-IO`, `EthernetIP`, …).
- **Timestamps (epoch ms):** `firstActivity`, `lastActivity` of the conversation.
- Volume: `packetsCount`, `bytesCount`, `flowCount`, `direction`.

**components/{id}/vulnerabilities** (`docs/api-samples/component_vulnerabilities.json`)
- `cve`, `title`, `summary`, `solution`, `links[]`.
- **Severity:** `CVSS` (0–10, sample had a **10.0** on a Rockwell Logix PLC), `CVSSTemporal`,
  `CVSSVersion`, `CVSSVectorString`.
- Lifecycle: `matchingTime` (when CV matched the CVE to this asset), `ackTime`/`ackAuthor`/
  `ackComment` (acknowledgement workflow), `reasons` (why it matched, e.g. `model-ref`).
- **45 of 180 components carry at least one CVE.**

**vulnerabilities** (global) — same shape, but the full 3,515-entry catalog, not asset-linked.
For "which asset is vulnerable" use the per-component endpoint above.

**presets / tags / sensors** — preset `id` + `label` + `filters`; tag `id`/`label`/`category`
(the source of Purdue-level and protocol semantics); sensors = the capture points.

---

## 5. Can the three alerts be built on this data?

| Alert | Category | Verdict | Grounded in | Honest caveat |
|---|---|---|---|---|
| **Asset went silent** | Operations | ✅ Buildable | `component.lastActivity` / `activity.lastActivity` (epoch ms) vs the newest timestamp in the dataset | Data is a **static PCAP import**, not a live feed — every timestamp sits inside one ~5-min capture window. "Silent" = last-seen significantly *before the capture's newest activity*. The detection logic is real and would work unchanged on live data; here it runs against the snapshot's clock, not wall-clock "now." |
| **Unexpected / unauthorized asset** | Security | ✅ Buildable (our policy) | `components` identity (IP/MAC/vendor/`public-ip`), `activities` (who connects to whom), Purdue-level `tags`, `externalCommunicationsCount` | CV **baselines are empty**, so we can't use native deviation. We declare an **expected-state policy** (known assets / allowed cross-zone links) and flag violations — e.g. an asset talking across Purdue levels, an unknown vendor reaching a controller, or external comms. Defensible and data-grounded; we just author the baseline ourselves. |
| **Vulnerable asset exposure** | **Free-choice (recommended)** | ✅ Strongest | `components/{id}/vulnerabilities` (real CVEs + CVSS) cross-referenced with `activities` (is the vulnerable asset actually communicating / reaching across zones) | None significant — this is the best-supported alert. 45 assets with CVEs, real CVSS scores up to 10.0, ack workflow. Lets us **prioritize by "vulnerable AND actively communicating across zones,"** which is genuine OT risk triage. |

**My honest read on the best three:** keep Operations = *silent device* and Security =
*unexpected asset / cross-zone connection*, and make the free choice **Vulnerable Asset
Exposure** — it's the richest, most defensible dataset here (real CVEs + CVSS + asset
linkage), it reuses the same comms graph the other two need, and it tells a strong OT-risk
story (NIST SP 800-82 / NERC CIP). The only thing to flag up front in the writeup is the
**static-snapshot caveat** for the silence alert, and that the **security alert uses a policy
we declare** (since CV baselines/events/groups are all empty in this instance).

---

## 6. What's broken / empty / surprising (one glance)
- 🟡 `flows` empty → use `activities` (aggregated layer is fully populated: 350 links).
- 🟡 `events`, `baselines`, `groups` all empty/absent → no native CV alarms or zones to ride
  on; we compute alerts and derive zones from Purdue **tags**.
- 🟡 No OpenAPI spec and no total-count header → endpoints confirmed by probing; counts by
  large-page reads.
- 🟢 Auth, inventory (180), comms graph (350 edges), and CVEs (3,515 catalog / 45 assets
  matched) are all live and rich — more than enough for all three alerts and the graph.
