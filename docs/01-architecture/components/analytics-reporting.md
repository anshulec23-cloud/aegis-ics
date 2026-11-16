# Risk analytics and reporting — `src/analytics.py`, `src/reporting.py`

## Analytics (FAIR-style)
`SUBSYSTEM_PROFILES` gives each node an equipment value, cleanup cost, base SLE, downtime $/h, criticality, and EPA and NERC-CIP fine ceilings. Unknown nodes get a default Tier-2 profile.

### `calculate_financial_analytics(db, device_id=None)`
Inputs: the last 60 telemetry rows, isolated devices, audit rows matching `VIOLATION|ISOLATION|ATTACK`, and the **simulator's active attack** for the device.

Threat index (0–100) = drift risk (≤30, °C/min × 5) + correlation risk (20 if the Pearson r of T vs P is < −0.6 or > 0.8, with variance guards) + boundary risk (15 each for T ≥ 45, P ≥ 6). It's raised to a fixed floor when a simulated attack is active (stuxnet 94.5, fdi 88, ddos 85, hmac 76, drift 52). The function then derives expected loss, prevented loss, incurred cost and regulatory exposure from the profiles. The design intent is a strict $0 baseline when nothing is wrong.

### `calculate_monte_carlo_distribution`
⚠️ Despite the name, this is **not** a Monte Carlo simulation. It multiplies the expected loss (or $50 when idle) by 12 fixed percentile multipliers (P05 ×0.15 … P99 ×5.5). Rename it, or implement real sampling (e.g. lognormal loss magnitude × Poisson frequency).

### `get_subsystem_financial_breakdown`
Per-node profile plus `active_outage_cost_per_hr` (the downtime rate if isolated, else 0).

## Reporting
`generate_incident_report_pdf(db, username, location) -> bytes` uses ReportLab Platypus to build a NIST SP 800-82r3 / 800-53r5 styled report:

1. Executive summary
2. Multi-node parameter inventory
3. Safety boundaries and Stuxnet rules
4. FAIR risk projections
5. Financial exposure and regulatory penalties
6. 12-point loss exceedance table
7. Threat vectors and incident breakdown
8. Telemetry dynamics plot
9. Audit trail (⚠️ titled "append-only", but the table isn't append-only)
10. Mitigation controls

All user-controlled strings are passed through `html.escape` before going into `Paragraph`. Served by `/api/report/download` (attachment), `/api/report/view` (inline) and `/api/report/save_dialog` (native Tk dialog in desktop mode).

## Caveat
The report includes simulated attack rows and seeded audit entries. Until they're separated (restructure plan Phase 1), don't hand these PDFs to anyone as evidence of real incidents.
