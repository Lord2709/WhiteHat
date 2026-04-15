# Expected Validation Checks

Use this checklist after running analysis with this dataset.

## CVE Discovery and Filtering

- CVEs in VA report that map to SBOM packages should appear in ranked vulnerabilities.
- `CVE-2019-10744` (legacy non-SBOM component) may appear in report context but should be omitted or deprioritized in package-based ranking.
- CVEs linked to `axios`, `jsonwebtoken`, `lodash`, `ws`, `minimist`, and `tar` should be strong candidates for output.

## Prioritization Behavior

- `jsonwebtoken` and `axios` related CVEs should rank high due to critical path and auth/payment blast radius.
- Regulatory scope (`PCI`, `GDPR`, `SOX`) should increase urgency.
- Connector signals should add context for affected systems and downstream impact.

## Team Assignment

- Auth/JWT-heavy findings should prefer members with `security` and `jwt` expertise.
- Operational/deployment-heavy findings may route to SRE/platform engineers.
- Completion dates should respect sprint-hour constraints and maintenance windows.

## Calendar and Ticket Quality

- Patch calendar should schedule high-priority work in nearest windows first.
- Tickets should include assignable owner, estimated hours, and target date.

## Resilience Checks

- App should still run if only verified-data mode is used (no LLM key).
- With Gemini key present, exploit/research fields should be richer.
