# Aegis ICS - Publication Figures & Evaluation Visualizations

This directory contains high-resolution empirical evaluation figures generated from experimental benchmark runs and hardware validation test suites.

## Figures Index

| Figure | Filename | Description | Source Benchmark |
|---|---|---|---|
| **Fig 1** | [`fig_stuxnet_attack.png`](fig_stuxnet_attack.png) | Sensor degradation vs. ground truth during Stuxnet-style low-and-slow frequency manipulation attack. Shows RPM deviations, trust decay, and trip triggering. | `tests/benchmark_results/stuxnet_attack_results.json` |
| **Fig 2** | [`fig_financial_risk.png`](fig_financial_risk.png) | Factor Analysis of Information Risk (FAIR) loss distribution, comparing annual expected loss with and without Aegis ICS active defense. | `tests/benchmark_results/financial_risk_results.json` |
| **Fig 3** | [`fig_nspn_heatmap.png`](fig_nspn_heatmap.png) | Neuro-Symbolic Petri Net transition probability heatmap and reachability state transitions under physical sensor perturbation. | `tests/benchmark_results/nspn_state_transitions.json` |
| **Fig 4** | [`fig_trust_evolution.png`](fig_trust_evolution.png) | Dynamic Bayesian trust score trajectories across five industrial transducers (Temperature, Pressure, Vibration, Current, RPM) during active attack injection. | `tests/benchmark_results/trust_evolution_data.json` |
| **Fig 5** | [`fig_latency_distribution.png`](fig_latency_distribution.png) | End-to-end edge inference latency distribution ($P_{50}$, $P_{95}$, $P_{99}$) across 50,000 real-time sensor cycles. | `tests/benchmark_results/latency_benchmarks.json` |
| **Fig 6** | [`fig_roc_curves.png`](fig_roc_curves.png) | ROC curves comparing Aegis ICS hybrid detector (Random Forest + NSPN) against isolation forest, autoencoder, and static threshold baselines. | `tests/benchmark_results/roc_curve_data.json` |

## Figure Generation

All figures can be deterministically reproduced using the automated generator script:

```bash
python tests/generate_graphs.py
```

This script reads raw empirical data from `tests/benchmark_results/` and generates publication-grade 300 DPI PNG visualizations using Matplotlib and Seaborn.
