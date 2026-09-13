# Aegis ICS — Offline Air-Gapped Vendor Bundles

This directory contains standalone, pre-compiled third-party vendor assets bundled directly with **Aegis ICS v2.5.0** to satisfy **100% Air-Gapped Industrial Facility Compliance** (NIST SP 800-82 Rev 3).

---

## Why Offline Vendor Bundling is Required

Critical Operational Technology (OT) and SCADA environments are deployed on isolated industrial control networks with **zero outbound internet connectivity**. Traditional web applications that import JavaScript or CSS from external Content Delivery Networks (CDNs) fail to render or introduce severe supply-chain attack vectors.

Aegis ICS bundles all required visual libraries locally.

---

## Bundled Assets

| File | Library | Size | Function in Aegis ICS |
|---|---|---|---|
| `chart.umd.js` | Chart.js (v4.4.x UMD) | ~205 KB | Powers dynamic real-time SCADA telemetry charting, monotone cubic spline smoothing, multi-node discrete grid charts, and Monte Carlo probability curves. |
| `tailwind.min.css` | Tailwind CSS | ~2.9 MB | Complete utility-first CSS framework providing responsive high-density layouts, CRT panel flexboxes, and modal styling without an npm build step. |
