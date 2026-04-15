# Enterprise Test Dataset (Synthetic, Realistic)

This dataset is designed for end-to-end testing of VulnPriority AI with realistic security operations inputs.
All data is synthetic but modeled after common payment-platform scenarios.

## Included Data

- `package.json`: Node.js payment API dependency manifest with intentionally vulnerable versions.
- `requirements.txt`: Python worker dependencies with realistic pinning.
- `va_report_q2_2026.txt`: VA/pentest report with finding IDs, CVEs, affected assets, and exploit notes.
- `team_profiles.json`: Security + engineering team profiles for assignment tests.
- `system_info.json`: System criticality, owner, regulatory scope, dependencies.
- `maintenance_windows.json`: Maintenance schedule for patch calendar testing.
- `vendor_advisories.json`: External advisory feed examples.
- `internal_docs.json`: Internal architecture/runbook snippets.
- `dependency_graph.json`: Service and package dependency flow.
- `config_payload_example.json`: Ready-to-save payload shape for `/api/config/save`.
- `expected_checks.md`: Validation checklist to verify pipeline quality.

## Quick Test Guide

1. Start backend:

```powershell
cd backend
..\.venv\Scripts\python.exe -m uvicorn main:app --reload --port 8000
```

2. Open app:

- Use `http://127.0.0.1:8000/`.

3. Configure page inputs:

- SBOM/Package input:
  - Upload `../test_dataset_enterprise_2026/package.json`.
- VA report:
  - Upload `../test_dataset_enterprise_2026/va_report_q2_2026.txt`.
- Team profiles:
  - Use `team_profiles.json` to create or bulk-import profiles (manual copy/paste per profile if needed).
- System details:
  - Copy from `system_info.json`.
- Maintenance windows:
  - Copy from `maintenance_windows.json`.
- Connectors:
  - Paste `vendor_advisories.json`, `internal_docs.json`, `dependency_graph.json` into connector inputs.

4. Run analysis and verify outputs using `expected_checks.md`.

## Realism Notes

- Includes mixed severity findings and at least one non-SBOM CVE to test filtering.
- Includes cross-team skills (SRE, backend, appsec, data engineering) for assignment behavior.
- Includes PCI + GDPR + SOX scope to trigger compliance multiplier behavior.
