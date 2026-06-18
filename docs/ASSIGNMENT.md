# Assignment Digest — Cisco TPM (AI Builder) Technical Exercise

## Core task
Using Cisco Cyber Vision (data + API + UI), build an **interactive prototype for a new alert
experience**: a standalone dashboard with an **Alerts page showing three new alerts** that
leverage CV data.

- Alert categories required: **security**, **operations**, and **one of our choice**.
- Example triggers given: sudden stop of device communication; an unexpected asset connecting.

## Required
- Connect to the center **programmatically via API** (docs at Center UI → Admin → API → Documentation).
- Fetch the required data.
- **Visualize communicational relations** between assets.

## Deliverables
- Git repository with code.
- Tabular and/or visual reports on results.
- Dashboard / visualizations / presentation artifacts.
- Short explanation of design choices + intended audience.
- Documentation + setup instructions, architecture/design notes, testing instructions.

## What they evaluate
| Area | Focus |
|---|---|
| Technical Quality | correctness, maintainability, architecture |
| Problem Solving | decision-making, prioritization under ambiguity |
| Communication | clarity of docs and explanations |
| Engineering Practices | testing, structure, version control |
| Product Thinking | user + operational considerations |
| Creativity | quality of optional improvements |

## Reference material (use to justify alert rationale)
- NIST SP 800-82r3 (OT security)
- NIS2 technical implementation guidance (ENISA)
- NERC CIP reliability standards

## Optional extensions (only after core is done)
Usability/DX, observability, scalability/perf, docs, extra visualizations, architectural
improvements, missing functionality. They want to know WHAT we chose, WHY, and the tradeoffs.

## Time budget
2–3 days.

## Access (do NOT commit — stored only in local .env / host dashboards)
Web UI, API docs path, login, and API key were provided in the assignment PDF. Keep them out
of git entirely.
