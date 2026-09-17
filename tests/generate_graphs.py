"""
Aegis ICS — Publication-Quality Graph Generator
================================================
Generates real graphs from benchmark data for inclusion in paper_draft.md.
Replaces all fabricated graph data with genuine empirical results.

Usage:
    python tests/generate_graphs.py

Requires: matplotlib, numpy
Reads from: tests/benchmark_results/*.json
Outputs to: docs/figures/*.png
"""

import os
import sys
import json
import numpy as np

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend for headless generation
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.ticker import FuncFormatter
    MPL_AVAILABLE = True
except ImportError:
    MPL_AVAILABLE = False
    print("[ERROR] matplotlib is required. Install: pip install matplotlib")
    sys.exit(1)

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "benchmark_results")
FIGURES_DIR = os.path.join(os.path.dirname(__file__), "..", "docs", "figures")
os.makedirs(FIGURES_DIR, exist_ok=True)


def dollar_formatter(x, pos):
    """Format axis ticks as dollar amounts."""
    if x >= 1_000_000:
        return f'${x/1_000_000:.1f}M'
    elif x >= 1_000:
        return f'${x/1_000:.0f}K'
    return f'${x:.0f}'


def graph_stuxnet_attack():
    """Graph 1: Coordinated Stuxnet Stress Attack Detection."""
    data_path = os.path.join(RESULTS_DIR, "stuxnet_attack_results.json")
    if not os.path.exists(data_path):
        print("  [SKIP] stuxnet_attack_results.json not found. Run benchmark_suite.py first.")
        return

    with open(data_path) as f:
        data = json.load(f)

    plt.style.use('seaborn-v0_8-whitegrid')
    fig, ax1 = plt.subplots(1, 1, figsize=(10, 4.5), dpi=300)
    ax2 = ax1.twinx()

    time_s = data["time_s"]
    summary = data["summary"]

    # Attack window shading
    attack_start = summary["attack_window_start_s"]
    attack_end = summary["attack_window_end_s"]
    ax1.axvspan(attack_start, attack_end, alpha=0.15, color='#fca5a5', label='Stuxnet Attack Window')

    # Temperature lines
    line_true_temp, = ax1.plot(time_s, data["true_temp"], color='#a93226', linewidth=1.0, alpha=0.9, label='True Temp (Physical)')
    line_spoof_temp, = ax1.plot(time_s, data["spoofed_temp"], color='#c0392b', linewidth=0.8, alpha=0.7, linestyle='--', label='Spoofed Temp (SCADA)')

    # Pressure lines
    line_true_pres, = ax1.plot(time_s, data["true_pressure"], color='#2980b9', linewidth=1.0, alpha=0.9, label='True Pressure (Physical)')
    line_spoof_pres, = ax1.plot(time_s, data["spoofed_pressure"], color='#3498db', linewidth=0.8, alpha=0.7, linestyle='--', label='Spoofed Pressure (SCADA)')

    # Anomaly score on right axis
    line_anomaly, = ax2.plot(time_s, data["anomaly_score"], color='#555555', linewidth=1.0, alpha=0.8, label='Aegis Anomaly Score')

    ax1.set_xlabel('Time (s)', fontsize=10)
    ax1.set_ylabel('Temperature (°C) / Pressure (bar)', fontsize=10)
    ax2.set_ylabel('Anomaly Score', fontsize=10, color='#374151')
    ax1.set_title('Simulated Coordinated Stress Attack (Stuxnet-style)', fontsize=11, pad=10)

    ax1.set_xlim(0, 1000)
    ax1.set_xticks([0, 200, 400, 600, 800, 1000])
    ax1.set_ylim(0, 68)
    ax1.set_yticks([0, 10, 20, 30, 40, 50, 60])

    ax2.set_ylim(-0.02, 1.10)
    ax2.set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])

    # Combined legend matching reference order
    handles = [
        line_true_temp,
        line_spoof_temp,
        line_true_pres,
        line_spoof_pres,
        mpatches.Patch(facecolor='#fca5a5', alpha=0.3, label='Stuxnet Attack Window'),
        line_anomaly
    ]
    labels = [h.get_label() for h in handles]
    ax1.legend(handles, labels, loc='upper left', fontsize=8, framealpha=0.9, edgecolor='#e5e7eb')

    ax1.grid(True, linestyle='-', linewidth=0.7, alpha=0.6)
    ax2.grid(False)
    plt.tight_layout()

    out_path = os.path.join(FIGURES_DIR, "fig_stuxnet_attack.png")
    plt.savefig(out_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  Saved: {out_path}")


def graph_financial_risk():
    """Graph 2: Real-time Financial Risk Projection & Mitigation."""
    data_path = os.path.join(RESULTS_DIR, "financial_risk_results.json")
    if not os.path.exists(data_path):
        print("  [SKIP] financial_risk_results.json not found. Run benchmark_suite.py first.")
        return

    with open(data_path) as f:
        data = json.load(f)

    plt.style.use('seaborn-v0_8-whitegrid')
    fig, ax1 = plt.subplots(1, 1, figsize=(10, 4.5), dpi=300)
    ax2 = ax1.twinx()

    time_h = data["time_hours"]
    isolation_h = data.get("isolation_triggered_hour", 18.0)

    # Unmitigated loss (black dotted)
    line_unmit, = ax1.plot(time_h, data["projected_unmitigated_loss"], color='#1f2937',
                           linewidth=1.2, linestyle=':', alpha=0.8, label='Projected Unmitigated Loss')

    # Actual incurred loss (solid red)
    line_actual, = ax1.plot(time_h, data["actual_incurred_loss"], color='#a93226',
                            linewidth=1.8, alpha=0.9, label='Actual Incurred Loss')

    # Damages prevented (green fill between)
    fill_prevented = ax1.fill_between(time_h, data["actual_incurred_loss"], data["projected_unmitigated_loss"],
                                      alpha=0.35, color='#27ae60', label='Damages Prevented ($)')

    # Threat index on right axis
    line_threat, = ax2.plot(time_h, data["threat_index"], color='#e67e22',
                            linewidth=1.8, alpha=0.9, label='Real-time Threat Index')

    # Isolation trigger line
    line_iso = ax1.axvline(x=isolation_h, color='#2980b9', linewidth=1.2, linestyle='--',
                           alpha=0.9, label='Aegis Isolation Triggered')

    ax1.set_xlabel('Time (Hours)', fontsize=10)
    ax1.set_ylabel('Financial Impact ($ USD)', fontsize=10)
    ax1.set_xlim(-0.5, 24.5)
    ax1.set_xticks([0, 5, 10, 15, 20])
    ax1.set_ylim(-5000, 420000)
    ax1.set_yticks([0, 50000, 100000, 150000, 200000, 250000, 300000, 350000, 400000])

    ax2.set_ylabel('Cyber Threat Index [0-1]', fontsize=10, color='#d35400')
    ax2.tick_params(axis='y', labelcolor='#d35400')
    ax2.set_ylim(-0.02, 1.12)
    ax2.set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])

    ax1.set_title('Real-time Financial Risk Projection & Mitigation', fontsize=11, pad=10)

    # Combined legend matching reference order
    handles = [
        line_unmit,
        line_actual,
        mpatches.Patch(facecolor='#27ae60', alpha=0.35, label='Damages Prevented ($)'),
        line_iso,
        line_threat
    ]
    labels = [h.get_label() for h in handles]
    ax1.legend(handles, labels, loc='upper left', fontsize=8,
               framealpha=0.9, edgecolor='#e5e7eb')

    ax1.grid(True, linestyle='-', linewidth=0.7, alpha=0.6)
    ax2.grid(False)
    plt.tight_layout()

    out_path = os.path.join(FIGURES_DIR, "fig_financial_risk.png")
    plt.savefig(out_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  Saved: {out_path}")


def graph_nspn_heatmap():
    """Graph 3: NSPN Decision Boundary Heatmap."""
    data_path = os.path.join(RESULTS_DIR, "nspn_decision_boundary.json")
    if not os.path.exists(data_path):
        print("  [SKIP] nspn_decision_boundary.json not found.")
        return

    with open(data_path) as f:
        data = json.load(f)

    fig, ax = plt.subplots(1, 1, figsize=(10, 8), dpi=150)

    matrix = np.array(data["safety_prob_matrix"])
    temp_range = data["temp_range"]
    pres_range = data["pressure_range"]

    im = ax.imshow(matrix, extent=[temp_range[0], temp_range[-1], pres_range[0], pres_range[-1]],
                   origin='lower', aspect='auto', cmap='RdYlGn', vmin=0, vmax=1)

    # Add contour at 0.5 threshold
    X, Y = np.meshgrid(temp_range, pres_range)
    cs = ax.contour(X, Y, matrix, levels=[0.5], colors=['black'], linewidths=[2], linestyles=['--'])
    ax.clabel(cs, fmt='P(safe)=0.50', fontsize=9)

    # Mark the Stuxnet danger zone
    ax.axvline(x=45.0, color='red', linewidth=1, linestyle=':', alpha=0.7)
    ax.axhline(y=6.0, color='red', linewidth=1, linestyle=':', alpha=0.7)
    ax.annotate('Stuxnet\nDanger Zone', xy=(55, 8), fontsize=9, color='red',
                fontweight='bold', ha='center')

    cbar = plt.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label('P(Safe | state, action)', fontsize=11)

    ax.set_xlabel('Temperature Setpoint (\u00b0C)', fontsize=12)
    ax.set_ylabel('Live Pressure (bar)', fontsize=12)
    ax.set_title('Neural Safety Policy Network (NSPN) — Learned Decision Boundary\n'
                 'P(Safe) heatmap across temperature-pressure state space',
                 fontsize=11, fontweight='bold')

    plt.tight_layout()
    out_path = os.path.join(FIGURES_DIR, "fig_nspn_heatmap.png")
    plt.savefig(out_path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  Saved: {out_path}")


def graph_trust_evolution():
    """Graph 4: Trust Score Evolution Under Multi-Phase Attack."""
    data_path = os.path.join(RESULTS_DIR, "trust_evolution_results.json")
    if not os.path.exists(data_path):
        print("  [SKIP] trust_evolution_results.json not found.")
        return

    with open(data_path) as f:
        data = json.load(f)

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 8), dpi=150, height_ratios=[3, 1],
                                    sharex=True, gridspec_kw={'hspace': 0.08})

    time_s = data["time_s"]
    trust = data["trust_score"]
    phases = data["phase"]

    # Phase coloring
    phase_colors = {
        "nominal": "#22c55e", "hmac_spoof": "#f97316",
        "thermal_creep": "#eab308", "stuxnet_attack": "#dc2626", "recovery": "#3b82f6"
    }
    phase_labels = {
        "nominal": "Nominal", "hmac_spoof": "HMAC Spoofing",
        "thermal_creep": "Thermal Creep", "stuxnet_attack": "Stuxnet Attack", "recovery": "Recovery"
    }

    # Phase background shading
    prev_phase = phases[0]
    start_idx = 0
    for i, p in enumerate(phases + [None]):
        if p != prev_phase:
            ax1.axvspan(time_s[start_idx], time_s[min(i, len(time_s)-1)],
                        alpha=0.08, color=phase_colors.get(prev_phase, '#gray'))
            ax2.axvspan(time_s[start_idx], time_s[min(i, len(time_s)-1)],
                        alpha=0.12, color=phase_colors.get(prev_phase, '#gray'))
            start_idx = i
            prev_phase = p

    # Trust score line
    ax1.plot(time_s, trust, color='#1f2937', linewidth=1.2, alpha=0.9)
    ax1.fill_between(time_s, trust, 0, alpha=0.15, color='#3b82f6')

    # Trust zone thresholds
    ax1.axhline(y=80, color='#22c55e', linewidth=0.8, linestyle='--', alpha=0.6)
    ax1.axhline(y=50, color='#eab308', linewidth=0.8, linestyle='--', alpha=0.6)
    ax1.axhline(y=30, color='#dc2626', linewidth=0.8, linestyle='--', alpha=0.6)
    ax1.text(time_s[-1] + 5, 85, 'TRUSTED', fontsize=7, color='#22c55e', fontweight='bold')
    ax1.text(time_s[-1] + 5, 55, 'DEGRADED', fontsize=7, color='#eab308', fontweight='bold')
    ax1.text(time_s[-1] + 5, 35, 'SUSPICIOUS', fontsize=7, color='#f97316', fontweight='bold')
    ax1.text(time_s[-1] + 5, 15, 'CRITICAL', fontsize=7, color='#dc2626', fontweight='bold')

    ax1.set_ylabel('Trust Score (%)', fontsize=11)
    ax1.set_ylim(-5, 105)
    ax1.set_title('Trust Score Evolution Under Multi-Phase Attack Scenario',
                  fontsize=11, fontweight='bold')
    ax1.grid(True, alpha=0.3)

    # Phase label subplot
    phase_patches = [mpatches.Patch(color=c, label=phase_labels.get(p, p), alpha=0.5)
                     for p, c in phase_colors.items()]
    ax2.legend(handles=phase_patches, loc='center', ncol=5, fontsize=8, framealpha=0.9)
    ax2.set_xlabel('Time Step', fontsize=11)
    ax2.set_ylabel('Phase', fontsize=9)
    ax2.set_yticks([])

    plt.tight_layout()
    out_path = os.path.join(FIGURES_DIR, "fig_trust_evolution.png")
    plt.savefig(out_path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  Saved: {out_path}")


def graph_latency_distribution():
    """Graph 5: Inference Latency Distribution Histograms."""
    data_path = os.path.join(RESULTS_DIR, "latency_benchmarks.json")
    if not os.path.exists(data_path):
        print("  [SKIP] latency_benchmarks.json not found.")
        return

    with open(data_path) as f:
        data = json.load(f)

    components = []
    if "rf_latency_ms" in data:
        components.append(("Random Forest", data["rf_latency_ms"], "#3b82f6"))
    if "nspn_latency_ms" in data:
        components.append(("NSPN (NumPy)", data["nspn_latency_ms"], "#22c55e"))
    if "hmac_latency_ms" in data:
        components.append(("HMAC-SHA256", data["hmac_latency_ms"], "#f97316"))

    if not components:
        print("  [SKIP] No latency data found.")
        return

    fig, axes = plt.subplots(1, len(components), figsize=(5 * len(components), 4), dpi=150)
    if len(components) == 1:
        axes = [axes]

    for ax, (name, stats, color) in zip(axes, components):
        samples = stats.get("raw_samples", [])
        if samples:
            ax.hist(samples, bins=40, color=color, alpha=0.7, edgecolor='white', linewidth=0.5)
            ax.axvline(x=stats["mean"], color='black', linewidth=1.5, linestyle='-',
                       label=f'Mean: {stats["mean"]:.3f}ms')
            ax.axvline(x=stats["p95"], color='#dc2626', linewidth=1, linestyle='--',
                       label=f'P95: {stats["p95"]:.3f}ms')
            ax.axvline(x=stats["p99"], color='#7c3aed', linewidth=1, linestyle=':',
                       label=f'P99: {stats["p99"]:.3f}ms')

        ax.set_xlabel('Latency (ms)', fontsize=10)
        ax.set_ylabel('Count', fontsize=10)
        ax.set_title(f'{name}\n(n={stats["n_iterations"]:,})', fontsize=10, fontweight='bold')
        ax.legend(fontsize=7, framealpha=0.9)
        ax.grid(True, alpha=0.2)

    fig.suptitle('Inference Latency Distribution (10,000 iterations)',
                 fontsize=12, fontweight='bold', y=1.02)
    plt.tight_layout()

    out_path = os.path.join(FIGURES_DIR, "fig_latency_distribution.png")
    plt.savefig(out_path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  Saved: {out_path}")


def graph_roc_curves():
    """Graph 6: Empirical ROC Curves for RF and NSPN."""
    metrics_path = os.path.join(os.path.dirname(__file__), "..", "src", "model", "training_metrics.json")
    if not os.path.exists(metrics_path):
        print("  [SKIP] training_metrics.json not found.")
        return

    with open(metrics_path) as f:
        data = json.load(f)

    fig, ax = plt.subplots(1, 1, figsize=(8, 6), dpi=150)

    # Plot random chance line
    ax.plot([0, 1], [0, 1], color='#9ca3af', linestyle='--', linewidth=1.2, label='Random Classifier (AUC = 0.500)')

    if "rf" in data and "roc_curve" in data["rf"]:
        rf_fpr = data["rf"]["roc_curve"]["fpr"]
        rf_tpr = data["rf"]["roc_curve"]["tpr"]
        rf_auc = data["rf"]["roc_auc"]
        ax.plot(rf_fpr, rf_tpr, color='#2563eb', linewidth=2.0,
                label=f'Random Forest 5D Anomaly Detector (AUC = {rf_auc:.4f})')

    if "nspn" in data and "roc_curve" in data["nspn"]:
        nspn_fpr = data["nspn"]["roc_curve"]["fpr"]
        nspn_tpr = data["nspn"]["roc_curve"]["tpr"]
        nspn_auc = data["nspn"]["roc_auc"]
        ax.plot(nspn_fpr, nspn_tpr, color='#16a34a', linewidth=2.0,
                label=f'Neural Safety Policy Network (AUC = {nspn_auc:.4f})')

    ax.set_xlim([-0.02, 1.02])
    ax.set_ylim([-0.02, 1.05])
    ax.set_xlabel('False Positive Rate (1 - Specificity)', fontsize=11)
    ax.set_ylabel('True Positive Rate (Sensitivity / Recall)', fontsize=11)
    ax.set_title('Empirical Receiver Operating Characteristic (ROC) Curves\nEvaluated on Complex Overlapping Cyber-Physical Telemetry',
                 fontsize=11, fontweight='bold')
    ax.legend(loc='lower right', fontsize=9, framealpha=0.9, edgecolor='#d1d5db')
    ax.grid(True, alpha=0.3)
    plt.tight_layout()

    out_path = os.path.join(FIGURES_DIR, "fig_roc_curves.png")
    plt.savefig(out_path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  Saved: {out_path}")


if __name__ == "__main__":
    print("\n" + "#" * 70)
    print("#  AEGIS ICS — PUBLICATION-QUALITY GRAPH GENERATOR")
    print("#  Generates real graphs from actual benchmark data")
    print("#" * 70)

    graph_stuxnet_attack()
    graph_financial_risk()
    graph_nspn_heatmap()
    graph_trust_evolution()
    graph_latency_distribution()
    graph_roc_curves()

    print(f"\nAll graphs saved to: {os.path.abspath(FIGURES_DIR)}")

