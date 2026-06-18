Run the Cyber Vision API connectivity + discovery smoke test.
1. Load `.claude/skills/cv-api-client/SKILL.md`.
2. Read CV_BASE_URL and CV_API_TOKEN from the backend `.env` (never print the token).
3. Hit a basic endpoint to confirm auth; print HTTP status only.
4. Enumerate components, flows/activities, vulnerabilities, events.
5. Save trimmed samples to docs/api-samples/ and update docs/API-FINDINGS.md.
6. Report a plain-language summary of what's available and any failures.
