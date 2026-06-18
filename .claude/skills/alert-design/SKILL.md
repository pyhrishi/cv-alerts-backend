# Skill: OT Alert Design

## When to use
Defining, scoping, or implementing any of the three required alerts.

## The alert contract (every alert is one object)
```
Alert {
  id: string
  category: "security" | "operations" | "custom"
  title: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  status: "active" | "acknowledged" | "resolved"
  detected_at: ISO8601
  asset(s): [ { id, name, ip, mac, type, zone } ]
  evidence: object        # the raw CV data points that triggered it (auditable)
  rationale: string       # WHY this matters in an OT context
  compliance_ref?: string # e.g. "NIST SP 800-82r3", "NERC CIP-007", "NIS2"
  recommended_action: string
}
```
Severity must be *derived from a documented rule*, not hand-waved. Write the rule down.

## The three alerts (grounded in real CV data — confirm against API-FINDINGS first)
1. **Operations — "Device went silent"**: an asset that was actively communicating has had
   no flow/activity for longer than its normal cadence (threshold configurable). Maps to the
   PDF's "sudden stop of communication" example. Data: flows/activities timestamps + inventory.
2. **Security — "Unexpected / unauthorized asset"**: a component appears that wasn't in a
   known baseline, OR communicates cross-zone in a way an OT Purdue model forbids, OR talks to
   an external/unknown address. Maps to "unexpected asset connected." Data: components + flows + groups.
3. **Free choice — pick ONE, justify it** (candidates, decide from real data):
   - **Vulnerability exposure**: a component with a known CVE is actively communicating
     (exploitable surface). Strong OT story, ties to NERC CIP-007 patch mgmt. Needs the
     vulnerabilities endpoint to be populated.
   - **Insecure protocol on critical asset**: cleartext/legacy industrial protocol observed
     to/from a controller. Ties to NIS2 / NIST 800-82 secure-comms guidance.
   - **New external conversation**: first-ever flow to an address outside the OT zone.
   Choose based on which underlying data is actually present and rich.

## OT context to cite (don't overclaim — reference, don't quote at length)
- NIST SP 800-82r3 — OT security baseline; asset inventory, monitoring, least functionality.
- NIS2 technical guidance — risk management, detection, reporting obligations.
- NERC CIP — CIP-002 (asset categorization), CIP-007 (system security/patching), CIP-010 (config/change monitoring).
Use these to make `rationale` and `compliance_ref` credible, since the audience is OT security teams.

## Tradeoffs to document
- Threshold tuning (silence window, baseline window) = false-positive vs missed-detection.
- Snapshot vs streaming: this exercise is poll-based snapshots; note real-time would need streaming.
- Baseline definition: how we decide "expected" assets (first poll? a stored allowlist?).
