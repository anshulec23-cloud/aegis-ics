import time
import html
import math
from datetime import datetime, timezone
from io import BytesIO
import socket
from sqlalchemy.orm import joinedload
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle

from database import TelemetryLog, AuditLog, DeviceState, Rule
from analytics import (
    calculate_financial_analytics,
    calculate_monte_carlo_distribution,
    get_subsystem_financial_breakdown,
    SUBSYSTEM_PROFILES
)
from trust_engine import get_device_trust_score, compute_device_trust_score


def generate_incident_report_pdf(db_session, username, location):
    """
    Generates an exhaustive, formal, publication-grade incident and compliance audit report
    adhering strictly to NIST SP 800-82 Rev 3 (Guide to OT/ICS Security) and NIST SP 800-53 Rev 5.

    Report Structure (10 Mandated Sections):
      1. Executive Incident Summary & Station Identification
      2. Multi-Node Edge SCADA Parameter Inventory (All ESP Nodes: ESP32_001 - ESP32_004)
      3. Physical Safeguard Boundaries & Stuxnet Enforcement Rules
      4. FAIR Quantitative Cyber-Physical Risk Framework
      5. Financial Loss Exposure, Outage Liabilities & Regulatory Penalties
      6. Monte Carlo 12-Point Probabilistic Loss Exceedance Distribution (P05 to P99)
      7. Cyber Threat Vectors & Security Incident Breakdown
      8. Sensor Telemetry Dynamics & Physical Waveform Plot
      9. Append-Only Chronological Security Audit Trail
     10. NIST SP 800-53 Rev 5 Mandated Technical Mitigations
    """
    buffer = BytesIO()
    # Letter dimensions: 612 x 792 pt. Margins: 36 pt (0.5 in). Usable width: 540 pt.
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    story = []

    styles = getSampleStyleSheet()

    # High-Assurance Industrial Color Palette (NIST / OT Cyber-Physical Standard)
    PRIMARY_NAVY = colors.HexColor('#0F172A')
    SECONDARY_SLATE = colors.HexColor('#1E293B')
    HEADER_ACCENT = colors.HexColor('#1E3A8A')
    CRIMSON_ACCENT = colors.HexColor('#991B1B')
    DARK_RED = colors.HexColor('#B91C1C')
    FOREST_GREEN = colors.HexColor('#15803D')
    AMBER_GOLD = colors.HexColor('#B45309')
    BG_LIGHT_GREY = colors.HexColor('#F8FAFC')
    BG_ALT_GREY = colors.HexColor('#F1F5F9')
    BORDER_GREY = colors.HexColor('#CBD5E1')
    BORDER_DARK = colors.HexColor('#94A3B8')
    TEXT_DARK = colors.HexColor('#0F172A')
    TEXT_MUTED = colors.HexColor('#475569')

    # Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=PRIMARY_NAVY,
        spaceAfter=2
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=CRIMSON_ACCENT,
        spaceAfter=5
    )
    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=13,
        textColor=PRIMARY_NAVY,
        spaceBefore=8,
        spaceAfter=3
    )
    body_style = ParagraphStyle(
        'StandardBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=TEXT_DARK,
        spaceAfter=4
    )
    body_bold = ParagraphStyle(
        'StandardBodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    meta_label = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=PRIMARY_NAVY
    )
    meta_val = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=TEXT_DARK
    )
    table_text = ParagraphStyle(
        'TableText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7,
        leading=9,
        textColor=TEXT_DARK
    )
    table_text_mono = ParagraphStyle(
        'TableTextMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=TEXT_DARK
    )
    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.2,
        leading=9.5,
        textColor=colors.white
    )

    # --- Header / Document Title Block ---
    story.append(Paragraph("AEGIS ICS SECURITY &amp; OT COMPLIANCE AUDIT REPORT", title_style))
    story.append(Paragraph("NIST SP 800-82 REV 3 &amp; NIST SP 800-53 REV 5 · INDUSTRIAL CONTROL SYSTEMS CYBERSECURITY AUDIT", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=PRIMARY_NAVY, spaceAfter=6))

    # --- Document Metadata & Computer / Station Login Control Block ---
    hostname = socket.gethostname()
    generated_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    meta_table_data = [
        [
            Paragraph("Document Standard:", meta_label),
            Paragraph("NIST SP 800-82r3 / NIST SP 800-53r5", meta_val),
            Paragraph("Authenticated Operator:", meta_label),
            Paragraph(html.escape(str(username)), meta_val)
        ],
        [
            Paragraph("Document Identifier:", meta_label),
            Paragraph("AEGIS-NIST-800-82-v2.5.0", meta_val),
            Paragraph("Station Coordinates:", meta_label),
            Paragraph(html.escape(str(location)), meta_val)
        ],
        [
            Paragraph("Generation Timestamp:", meta_label),
            Paragraph(generated_time, meta_val),
            Paragraph("Host Computer Name:", meta_label),
            Paragraph(html.escape(str(hostname)), meta_val)
        ],
        [
            Paragraph("Classification:", meta_label),
            Paragraph("RESTRICTED / OT OPERATIONS CRITICAL", meta_val),
            Paragraph("Master Architecture:", meta_label),
            Paragraph("Multiplexed Master-Slave Gateway (4 Nodes)", meta_val)
        ]
    ]
    meta_table = Table(meta_table_data, colWidths=[110, 160, 110, 160])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT_GREY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER_GREY),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 6))

    # =========================================================================
    # SECTION 1: Executive Summary & System Control Briefing
    # =========================================================================
    story.append(Paragraph("1. Executive Incident Summary &amp; System Control Briefing", h2_style))
    story.append(Paragraph(
        "This security audit and forensic incident report documents the real-time operational posture, threat landscape, "
        "and physical safety enforcement boundaries across all field slave programmable logic controllers (PLCs) and "
        "sensor nodes monitored by the Aegis Industrial Control Systems (ICS) Master Gateway. Real-time telemetry is "
        "continuously analyzed via the 4-factor continuous trust engine and physical safety boundary policies to ensure "
        "rapid microsegmentation and autonomous quarantine upon cryptographic failure, telemetry drift, or out-of-boundary excursions.",
        body_style
    ))

    # =========================================================================
    # SECTION 2: Multi-Node Edge SCADA Parameter Inventory (All ESP Nodes)
    # =========================================================================
    story.append(Paragraph("2. NIST SP 800-82r3 Multi-Node Edge SCADA Parameter Inventory (All ESP Nodes)", h2_style))
    story.append(Paragraph(
        "Exhaustive real-time telemetry inventory of all edge sensor/PLC nodes communicating over the industrial fieldbus. "
        "Values represent latest verified telemetry ingested into the system database:",
        body_style
    ))

    cluster_device_ids = ["ESP32_001", "ESP32_002", "ESP32_003", "ESP32_004"]
    # Check if any additional device states exist in DB
    extra_states = db_session.query(DeviceState).all()
    for es in extra_states:
        if es.device_id and es.device_id not in cluster_device_ids:
            cluster_device_ids.append(es.device_id)
    cluster_device_ids.sort()

    # Table 2A: Node Network State & Trust Overview
    node_overview_headers = [
        Paragraph("Slave Node ID", table_header),
        Paragraph("Designated Subsystem", table_header),
        Paragraph("Industrial Plant Zone", table_header),
        Paragraph("Criticality", table_header),
        Paragraph("Network Status", table_header),
        Paragraph("Trust Score", table_header),
        Paragraph("NIST Risk Posture", table_header)
    ]
    node_overview_rows = [node_overview_headers]

    for did in cluster_device_ids:
        d_state = db_session.query(DeviceState).filter_by(device_id=did).first()
        is_isolated = d_state.is_isolated if d_state else False
        trust_val = get_device_trust_score(did, db_session)
        profile = SUBSYSTEM_PROFILES.get(did, {})

        subsystem_name = profile.get("name", f"Field Node {did}")
        zone_name = profile.get("zone", "Auxiliary Bus")
        criticality = profile.get("criticality", "STANDARD")

        status_text = "ISOLATED (QUARANTINED)" if is_isolated else "ONLINE / ASSURED"
        status_color = DARK_RED if is_isolated else FOREST_GREEN
        status_style = ParagraphStyle(f'StatusStyle_{did}', parent=table_text, textColor=status_color, fontName="Helvetica-Bold")

        trust_pct = f"{trust_val:.1f}%"
        if trust_val >= 80:
            posture_text = "LOW RISK (ASSURED)"
            t_color = FOREST_GREEN
        elif trust_val >= 50:
            posture_text = "ELEVATED CONCERN"
            t_color = AMBER_GOLD
        else:
            posture_text = "CRITICAL / COMPROMISED"
            t_color = DARK_RED

        t_style = ParagraphStyle(f'TrustStyle_{did}', parent=table_text, textColor=t_color, fontName="Helvetica-Bold")

        node_overview_rows.append([
            Paragraph(html.escape(str(did)), table_text_mono),
            Paragraph(html.escape(str(subsystem_name)), table_text),
            Paragraph(html.escape(str(zone_name)), table_text),
            Paragraph(html.escape(str(criticality)), table_text),
            Paragraph(status_text, status_style),
            Paragraph(trust_pct, t_style),
            Paragraph(posture_text, t_style)
        ])

    t_node_overview = Table(node_overview_rows, colWidths=[65, 110, 110, 65, 75, 45, 70])
    t_node_overview.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_NAVY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GREY),
    ]))
    story.append(t_node_overview)
    story.append(Spacer(1, 5))

    # Table 2B: Detailed Sensor Parameter Telemetry per ESP Node
    story.append(Paragraph("<b>Table 2.1: Real-Time Sensor Telemetry &amp; Parameter Matrix (All ESP Nodes)</b>", body_style))
    param_headers = [
        Paragraph("Node ID", table_header),
        Paragraph("Temp (°C)", table_header),
        Paragraph("Pressure (bar)", table_header),
        Paragraph("Vibration (g)", table_header),
        Paragraph("Rotor RPM", table_header),
        Paragraph("Current (A)", table_header),
        Paragraph("Humidity (%)", table_header),
        Paragraph("RSSI (dBm)", table_header),
        Paragraph("Anomaly Flag", table_header),
        Paragraph("Last Reading (UTC)", table_header)
    ]
    param_rows = [param_headers]

    for did in cluster_device_ids:
        last_log = db_session.query(TelemetryLog).filter_by(device_id=did).order_by(TelemetryLog.timestamp.desc()).first()
        if last_log:
            temp_str = f"{last_log.temperature:.2f} °C" if last_log.temperature is not None else "N/A"
            pres_str = f"{last_log.pressure:.2f} bar" if last_log.pressure is not None else "N/A"
            vib_str = f"{last_log.vibration:.2f} g" if last_log.vibration is not None else "N/A"
            hall_str = f"{last_log.hall_effect:.0f} RPM" if last_log.hall_effect is not None else "N/A"
            curr_str = f"{last_log.current:.2f} A" if last_log.current is not None else "N/A"
            hum_str = f"{last_log.humidity:.1f} %" if last_log.humidity is not None else "N/A"
            rssi_str = f"{last_log.rssi:.1f} dBm" if last_log.rssi is not None else "N/A"

            if last_log.is_anomaly:
                anom_text = "ANOMALOUS / TAMPERED"
                anom_style = ParagraphStyle(f'AnomStyle_{did}', parent=table_text, textColor=DARK_RED, fontName="Helvetica-Bold")
            else:
                anom_text = "NORMAL"
                anom_style = ParagraphStyle(f'AnomStyle_{did}', parent=table_text, textColor=FOREST_GREEN, fontName="Helvetica-Bold")

            ts_val = last_log.timestamp
            if isinstance(ts_val, (int, float)):
                ts_str = datetime.fromtimestamp(ts_val, timezone.utc).strftime('%H:%M:%S UTC')
            else:
                ts_str = str(ts_val)[:19]
        else:
            # Standby state if telemetry log not yet received
            temp_str = "STANDBY"
            pres_str = "STANDBY"
            vib_str = "STANDBY"
            hall_str = "STANDBY"
            curr_str = "STANDBY"
            hum_str = "STANDBY"
            rssi_str = "STANDBY"
            anom_text = "NOMINAL (READY)"
            anom_style = ParagraphStyle(f'AnomStyle_{did}', parent=table_text, textColor=TEXT_MUTED, fontName="Helvetica-Bold")
            ts_str = "Awaiting Packet"

        param_rows.append([
            Paragraph(html.escape(str(did)), table_text_mono),
            Paragraph(html.escape(temp_str), table_text),
            Paragraph(html.escape(pres_str), table_text),
            Paragraph(html.escape(vib_str), table_text),
            Paragraph(html.escape(hall_str), table_text),
            Paragraph(html.escape(curr_str), table_text),
            Paragraph(html.escape(hum_str), table_text),
            Paragraph(html.escape(rssi_str), table_text),
            Paragraph(anom_text, anom_style),
            Paragraph(html.escape(ts_str), table_text)
        ])

    t_params = Table(param_rows, colWidths=[55, 48, 55, 50, 52, 48, 48, 52, 67, 65])
    t_params.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), SECONDARY_SLATE),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 3),
        ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GREY),
    ]))
    story.append(t_params)
    story.append(Spacer(1, 6))

    # =========================================================================
    # SECTION 3: Physical Safeguard Boundaries & Stuxnet Enforcement Rules
    # =========================================================================
    story.append(Paragraph("3. Physical Safeguard Boundaries &amp; Stuxnet Enforcement Rules", h2_style))
    story.append(Paragraph(
        "Active operational setpoint thresholds and physical cross-variable enforcement interlocks stored in the gateway "
        "safety kernel. In accordance with NIST SP 800-82r3 Section 6.2, setpoint commands that violate physical boundaries "
        "or multi-variable correlation policies are dropped immediately prior to transmission to the actuator bus:",
        body_style
    ))

    # Query active rules from DB
    active_rules = db_session.query(Rule).all()
    rules_dict = {r.key: (r.value, r.description) for r in active_rules}

    rules_table_headers = [
        Paragraph("Safety Parameter", table_header),
        Paragraph("Boundary Key", table_header),
        Paragraph("Enforced Value", table_header),
        Paragraph("Operational Safety Rule &amp; Boundary Description", table_header)
    ]
    rules_table_rows = [rules_table_headers]

    rule_display_order = [
        ("temp_min", "Temperature Lower Bound", "°C"),
        ("temp_max", "Temperature Upper Bound", "°C"),
        ("pressure_min", "Pressure Lower Bound", "bar"),
        ("pressure_max", "Pressure Upper Bound", "bar"),
    ]

    for key, label, unit in rule_display_order:
        val, desc = rules_dict.get(key, (0.0, "Standard operational limit"))
        rules_table_rows.append([
            Paragraph(html.escape(label), table_text),
            Paragraph(html.escape(key), table_text_mono),
            Paragraph(f"<b>{val:.2f} {unit}</b>", table_text),
            Paragraph(html.escape(str(desc)), table_text)
        ])

    t_rules = Table(rules_table_rows, colWidths=[120, 95, 75, 250])
    t_rules.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_NAVY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GREY),
    ]))
    story.append(t_rules)
    story.append(Spacer(1, 4))

    # Multi-Variable Stuxnet Prevention Policies Box
    stuxnet_policies = [
        "<b>Interlock Rule 1 (Coordinated Overpressure &amp; Temperature Prevention)</b>: Temperature &gt; 45.0°C and Pressure &gt;= 6.0 bar is strictly prohibited. Dispatched setpoints violating this condition are blocked with HTTP 403, and the target node is flagged for inspection.",
        "<b>Interlock Rule 2 (Safeguard Boundary Inversion Prevention)</b>: Rule kernel enforces temp_min &lt; temp_max and pressure_min &lt; pressure_max. Inverted boundary submissions are rejected and logged under NIST AU-2.",
        "<b>Interlock Rule 3 (Centrifugal Resonance &amp; Vibration Suppression)</b>: Rotor speed exceeding 3,000 RPM coupled with vibration &gt; 3.0 g triggers automated microsegmentation to prevent casing rupture.",
        "<b>Interlock Rule 4 (Type &amp; Invariance Hardening)</b>: Strict scalar numeric typing enforced; boolean payloads, NaN, and +/-Inf setpoints are rejected at the parser layer."
    ]
    for p_text in stuxnet_policies:
        story.append(Paragraph(f"• {p_text}", body_style))
    story.append(Spacer(1, 4))

    # =========================================================================
    # SECTION 4: FAIR Quantitative Cyber-Physical Risk Framework
    # =========================================================================
    story.append(Paragraph("4. FAIR Quantitative Cyber-Physical Risk Projections", h2_style))
    story.append(Paragraph(
        "Factor Analysis of Information Risk (FAIR) quantitative modeling evaluates empirical threat event frequencies, "
        "system vulnerability factors, and loss event magnitudes derived from real-time telemetry and isolation history:",
        body_style
    ))

    fin = calculate_financial_analytics(db_session)
    fair_metrics = fin.get("fair_model", {})

    tef = fair_metrics.get("tef", 0.0)
    vuln_pct = fair_metrics.get("vulnerability_pct", 0.0)
    lef = fair_metrics.get("lef", 0.0)
    primary_loss = fair_metrics.get("primary_loss", 0.0)
    secondary_loss = fair_metrics.get("secondary_loss", 0.0)
    risk_tier = fair_metrics.get("risk_tier", "NOMINAL")
    rosi_pct = fin.get("capital_allocation", {}).get("rosi_percentage", 0.0)
    threat_idx = fin.get("threat_index", 0.0)

    tier_color = DARK_RED if risk_tier == "CRITICAL" else (AMBER_GOLD if risk_tier == "ELEVATED" else FOREST_GREEN)
    tier_style = ParagraphStyle('TierStyle', parent=table_text, textColor=tier_color, fontName="Helvetica-Bold")

    fair_data = [
        [Paragraph("FAIR Risk Parameter", table_header), Paragraph("Quantified Value", table_header), Paragraph("Model Derivation &amp; Operational Context", table_header)],
        [Paragraph("Threat Event Frequency (TEF)", table_text), Paragraph(f"<b>{tef:.2f} events/yr</b>", table_text), Paragraph("Calculated from historical physical boundary violations and isolation events", table_text)],
        [Paragraph("Vulnerability Factor (%)", table_text), Paragraph(f"<b>{vuln_pct:.1f}%</b>", table_text), Paragraph("Empirical ratio of threat capability vs. active microsegmentation strength", table_text)],
        [Paragraph("Loss Event Frequency (LEF)", table_text), Paragraph(f"<b>{lef:.3f} events/yr</b>", table_text), Paragraph("Composite probability of a successful cyber-physical breach per operating year", table_text)],
        [Paragraph("Primary Loss Magnitude", table_text), Paragraph(f"<b>${primary_loss:,.2f}</b>", table_text), Paragraph("Direct equipment damage, mechanical casing replacement, and local remediation", table_text)],
        [Paragraph("Secondary Loss Magnitude", table_text), Paragraph(f"<b>${secondary_loss:,.2f}</b>", table_text), Paragraph("Environmental liabilities, regulatory fines, and grid reliability penalties", table_text)],
        [Paragraph("Threat Index &amp; Risk Tier", table_text), Paragraph(f"<b>{threat_idx:.1f}/100 — {risk_tier}</b>", tier_style), Paragraph("Multi-sensor drift, boundary, and correlation risk score", table_text)],
        [Paragraph("Return on Security Investment", table_text), Paragraph(f"<b>{rosi_pct:,.1f}% ROSI</b>", table_text), Paragraph("Realized capital savings ratio relative to annual cybersecurity tooling budget", table_text)],
    ]
    t_fair = Table(fair_data, colWidths=[140, 110, 290])
    t_fair.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_NAVY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GREY),
    ]))
    story.append(t_fair)
    story.append(Spacer(1, 6))

    # =========================================================================
    # SECTION 5: Financial Loss Exposure, Outage Liabilities & Regulatory Penalties
    # =========================================================================
    story.append(Paragraph("5. Financial Loss Exposure, Outage Liabilities &amp; Regulatory Penalties", h2_style))
    story.append(Paragraph(
        "Quantitative financial impact breakdown including Annualized Loss Expectancy (ALE), Single Loss Expectancy (SLE), "
        "per-subsystem Mean Time to Recover (MTTR) downtime liabilities, and statutory regulatory penalties:",
        body_style
    ))

    ale_metrics = fin.get("ale_framework", {})
    sle = ale_metrics.get("sle", 0.0)
    aro = ale_metrics.get("aro", 0.0)
    ale = ale_metrics.get("ale", 0.0)

    incurred_cost = fin.get("incurred_cost", 0.0)
    expected_loss = fin.get("expected_loss", 0.0)
    prevented_cost = fin.get("prevented_cost", 0.0)

    reg = fin.get("regulatory_exposure", {})
    epa_fines = reg.get("epa_environmental", 0.0)
    nerc_fines = reg.get("nerc_cip_critical_infra", 0.0)
    nis2_fines = reg.get("nis2_directive", 0.0)
    total_reg = reg.get("total_regulatory_exposure", 0.0)

    fin_summary_headers = [
        Paragraph("Financial Category", table_header),
        Paragraph("Monetary Assessment", table_header),
        Paragraph("Accounting Basis &amp; Calculation Formula", table_header)
    ]
    fin_summary_rows = [
        fin_summary_headers,
        [Paragraph("Single Loss Expectancy (SLE)", table_text), Paragraph(f"<b>${sle:,.2f}</b>", table_text), Paragraph("Total capital valuation of affected high-exotherm and turbine hardware", table_text)],
        [Paragraph("Annualized Rate of Occurrence (ARO)", table_text), Paragraph(f"<b>{aro:.2f} occurrences/yr</b>", table_text), Paragraph("Empirical occurrence frequency derived from active system threat index", table_text)],
        [Paragraph("Annualized Loss Expectancy (ALE)", table_text), Paragraph(f"<b>${ale:,.2f} / yr</b>", table_text), Paragraph("ALE = SLE × ARO (Statutory annualized cyber-physical financial liability)", table_text)],
        [Paragraph("Incurred Incident Cost", table_text), Paragraph(f"<b>${incurred_cost:,.2f}</b>", table_text), Paragraph("Direct triage and investigation overhead ($5,000 per violation/isolation)", table_text)],
        [Paragraph("Projected Downtime Liability", table_text), Paragraph(f"<b>${expected_loss:,.2f}</b>", table_text), Paragraph("Probabilistic loss estimated from sensor drift and cross-variable correlation", table_text)],
        [Paragraph("Net Exposure (Incurred + Projected)", table_text), Paragraph(f"<b>${(incurred_cost + expected_loss):,.2f}</b>", table_text), Paragraph("Total combined active financial liability exposure across all nodes", table_text)],
        [Paragraph("Realized Capital Savings", table_text), Paragraph(f"<b>${prevented_cost:,.2f}</b>", table_text), Paragraph("Capital savings achieved by blocking physical casing ruptures ($400,000 each)", table_text)],
    ]
    t_fin_summary = Table(fin_summary_rows, colWidths=[140, 110, 290])
    t_fin_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), SECONDARY_SLATE),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GREY),
    ]))
    story.append(t_fin_summary)
    story.append(Spacer(1, 4))

    # Subsystem MTTR Hourly Outage Liabilities Table
    story.append(Paragraph("<b>Table 5.1: Critical Subsystem MTTR Downtime Liabilities &amp; Outage Rates</b>", body_style))
    subsystem_rows = [[
        Paragraph("Subsystem ID &amp; Name", table_header),
        Paragraph("Zone Location", table_header),
        Paragraph("Hourly Outage", table_header),
        Paragraph("4h MTTR Outage", table_header),
        Paragraph("8h MTTR Outage", table_header),
        Paragraph("24h Catastrophic", table_header),
        Paragraph("Outage Status", table_header)
    ]]

    subsystem_list = get_subsystem_financial_breakdown(db_session)
    for sub in subsystem_list:
        sub_did = sub["device_id"]
        sub_name = sub["name"]
        hr_rate = sub["downtime_rate_per_hour"]
        is_sub_isolated = sub["is_isolated"]

        status_str = "ACTIVE OUTAGE" if is_sub_isolated else "ONLINE (NORMAL)"
        color_sub = DARK_RED if is_sub_isolated else FOREST_GREEN
        style_sub = ParagraphStyle(f'SubOutage_{sub_did}', parent=table_text, textColor=color_sub, fontName="Helvetica-Bold")

        subsystem_rows.append([
            Paragraph(f"<b>{sub_did}</b><br/>{html.escape(sub_name)}", table_text),
            Paragraph(html.escape(sub["zone"]), table_text),
            Paragraph(f"${hr_rate:,.2f}/hr", table_text),
            Paragraph(f"${(hr_rate * 4):,.2f}", table_text),
            Paragraph(f"${(hr_rate * 8):,.2f}", table_text),
            Paragraph(f"${(hr_rate * 24):,.2f}", table_text),
            Paragraph(status_str, style_sub)
        ])

    t_subsystems = Table(subsystem_rows, colWidths=[95, 105, 68, 68, 68, 72, 64])
    t_subsystems.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_NAVY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 3),
        ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GREY),
    ]))
    story.append(t_subsystems)
    story.append(Spacer(1, 4))

    # Regulatory Liabilities Summary
    story.append(Paragraph(
        f"<b>Statutory Regulatory Penalties Exposure:</b> EPA Clean Air/Water Act Non-Compliance: <b>${epa_fines:,.2f}</b> · "
        f"NERC-CIP Critical Infrastructure Sanctions: <b>${nerc_fines:,.2f}</b> · "
        f"EU NIS2 Directive Penalties: <b>${nis2_fines:,.2f}</b> · "
        f"Total Combined Regulatory Exposure: <b>${total_reg:,.2f}</b>",
        body_style
    ))
    story.append(Spacer(1, 4))

    # =========================================================================
    # SECTION 6: Monte Carlo 12-Point Loss Exceedance Distribution (P05 to P99)
    # =========================================================================
    story.append(Paragraph("6. Monte Carlo 12-Point Loss Exceedance Distribution (P05 to P99)", h2_style))
    story.append(Paragraph(
        "A 12-point Monte Carlo stochastic loss distribution evaluates catastrophic tail risk (P05 median to P99 extreme), "
        "quantifying the probability that annualized financial losses will exceed specified monetary thresholds:",
        body_style
    ))

    mc_distribution = calculate_monte_carlo_distribution(db_session)
    mc_headers = [
        Paragraph("Percentile", table_header),
        Paragraph("Probability of Exceedance", table_header),
        Paragraph("Statistical Risk Tier", table_header),
        Paragraph("Projected Monetary Loss (USD)", table_header),
        Paragraph("Risk Mitigation Action Threshold", table_header)
    ]
    mc_rows = [mc_headers]

    for item in mc_distribution:
        pct_label = item["percentile"]
        prob = item["probability"]
        loss = item["loss_usd"]

        if pct_label in ("P05", "P10", "P20"):
            risk_tier_str = "Operational Noise"
            action_str = "Standard Continuous Monitoring"
            row_color = TEXT_DARK
        elif pct_label in ("P30", "P40", "P50"):
            risk_tier_str = "Expected Loss (Median)"
            action_str = "Operational Reserve Allocation"
            row_color = PRIMARY_NAVY
        elif pct_label in ("P60", "P70", "P80"):
            risk_tier_str = "Elevated Stress Risk"
            action_str = "Automated Safeguard Throttle"
            row_color = AMBER_GOLD
        else:
            risk_tier_str = "Catastrophic Tail Risk"
            action_str = "Hard Interlock & Safe Shutdown"
            row_color = DARK_RED

        mc_style = ParagraphStyle(f'MCStyle_{pct_label}', parent=table_text, textColor=row_color, fontName="Helvetica-Bold")

        mc_rows.append([
            Paragraph(f"<b>{pct_label}</b>", table_text_mono),
            Paragraph(f"{prob:.1f}%", table_text),
            Paragraph(risk_tier_str, mc_style),
            Paragraph(f"<b>${loss:,.2f}</b>", mc_style),
            Paragraph(action_str, table_text)
        ])

    t_mc = Table(mc_rows, colWidths=[65, 105, 105, 120, 145])
    t_mc.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_NAVY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GREY),
    ]))
    story.append(t_mc)
    story.append(Spacer(1, 6))

    # =========================================================================
    # SECTION 7: Cyber Threat Vectors & Security Incident Breakdown
    # =========================================================================
    story.append(Paragraph("7. Cyber Threat Vectors &amp; Security Incident Breakdown", h2_style))
    story.append(Paragraph(
        "Categorized record of all cyber security attack vectors identified, blocked, or isolated during system operation:",
        body_style
    ))

    attack_headers = [
        Paragraph("Attack Vector / Incident", table_header),
        Paragraph("Timestamp (UTC)", table_header),
        Paragraph("Logged-in Operator &amp; Coords", table_header),
        Paragraph("Severity &amp; Action", table_header),
        Paragraph("Target Subsystem &amp; Forensic Impact", table_header)
    ]
    attack_rows = [attack_headers]

    audit_violations = db_session.query(AuditLog).options(joinedload(AuditLog.user)).filter(
        (AuditLog.action.like("%VIOLATION%")) |
        (AuditLog.action.like("%ISOLATION%")) |
        (AuditLog.action.like("%ATTACK%"))
    ).order_by(AuditLog.timestamp.desc()).limit(25).all()

    if not audit_violations:
        attack_rows.append([
            Paragraph("No Cyber Attacks Detected", table_text),
            Paragraph(datetime.now(timezone.utc).strftime('%H:%M:%S UTC'), table_text),
            Paragraph(f"<b>{html.escape(str(username))}</b><br/>{html.escape(str(location))}", table_text),
            Paragraph("LOW · NOMINAL", table_text),
            Paragraph("No security violations or isolation events recorded in audit history.", table_text)
        ])
    else:
        for a in reversed(audit_violations):
            if hasattr(a.timestamp, "strftime"):
                ts_str = a.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(a.timestamp, (int, float)):
                ts_str = datetime.fromtimestamp(a.timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            else:
                ts_str = str(a.timestamp or '')

            u_name = a.user.username if a.user else (username or "SYSTEM")
            u_loc = a.location if a.location else (location or "Control Terminal")

            vec_name = "Security Violation"
            sev_text = "HIGH"
            sev_color = DARK_RED
            if "STUXNET" in a.action or "Stuxnet" in (a.details or ""):
                vec_name = "Stuxnet Coordinated Hazard"
                sev_text = "CRITICAL"
            elif "ISOLATION" in a.action or "HMAC" in (a.details or ""):
                vec_name = "Telemetry Injection / HMAC Tamper"
                sev_text = "HIGH"
            elif "PRIVILEGE" in a.action or "thresholds" in (a.details or "") or "RULES" in a.action:
                vec_name = "Privilege Escalation / Rule Tamper"
                sev_text = "MEDIUM"
                sev_color = AMBER_GOLD
            elif "SPIKE" in a.action or "FDI" in (a.details or ""):
                vec_name = "False Data Injection (FDI)"
                sev_text = "HIGH"

            sev_style = ParagraphStyle('SevStyle', parent=table_text, textColor=sev_color, fontName="Helvetica-Bold")
            act_text = f"<b>{sev_text}</b><br/><font color='#15803D'>ISOLATED</font>"

            attack_rows.append([
                Paragraph(html.escape(str(vec_name)), table_text),
                Paragraph(html.escape(str(ts_str)), table_text),
                Paragraph(f"<b>{html.escape(str(u_name))}</b><br/><font size=6 color='#475569'>{html.escape(str(u_loc))}</font>", table_text),
                Paragraph(act_text, table_text),
                Paragraph(html.escape(str(a.details or "")), table_text)
            ])

    t_attack = Table(attack_rows, colWidths=[105, 80, 110, 80, 165])
    t_attack.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), SECONDARY_SLATE),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GREY),
    ]))
    story.append(t_attack)
    story.append(Spacer(1, 6))

    # =========================================================================
    # SECTION 8: Sensor Telemetry Dynamics & Physical Waveform Plot
    # =========================================================================
    story.append(Paragraph("8. Sensor Telemetry Dynamics &amp; Physical Waveform Plot", h2_style))
    telemetry = db_session.query(TelemetryLog).order_by(TelemetryLog.timestamp.desc()).limit(35).all()

    if telemetry:
        chrono_telemetry = list(reversed(telemetry))
        valid_telemetry = [t for t in chrono_telemetry if t.temperature is not None and t.pressure is not None]
        if valid_telemetry:
            drawing = Drawing(540, 120)
            drawing.add(Rect(0, 0, 540, 120, fillColor=BG_LIGHT_GREY, strokeColor=BORDER_GREY, strokeWidth=0.5))

            temp_pts = []
            pres_pts = []
            for idx, t in enumerate(valid_telemetry):
                x = 50 + (idx / max(1, len(valid_telemetry) - 1)) * 440
                y_temp = 15 + (min(80.0, max(0.0, float(t.temperature))) / 80.0) * 85
                y_pres = 15 + (min(10.0, max(0.0, float(t.pressure))) / 10.0) * 85
                temp_pts.append((x, y_temp))
                pres_pts.append((x, y_pres))

            for y_val in [15, 36.25, 57.5, 78.75, 100]:
                drawing.add(Line(50, y_val, 490, y_val, strokeColor=colors.HexColor('#E2E8F0'), strokeWidth=0.5))

            for i in range(len(temp_pts) - 1):
                p1 = temp_pts[i]
                p2 = temp_pts[i + 1]
                drawing.add(Line(p1[0], p1[1], p2[0], p2[1], strokeColor=PRIMARY_NAVY, strokeWidth=1.5))

            for i in range(len(pres_pts) - 1):
                p1 = pres_pts[i]
                p2 = pres_pts[i + 1]
                drawing.add(Line(p1[0], p1[1], p2[0], p2[1], strokeColor=CRIMSON_ACCENT, strokeWidth=1, strokeDashArray=[3, 3]))

            drawing.add(String(10, 100, "Temp (°C)", fontName="Helvetica-Bold", fontSize=7, fillColor=PRIMARY_NAVY))
            drawing.add(String(498, 100, "Pres (bar)", fontName="Helvetica-Bold", fontSize=7, fillColor=CRIMSON_ACCENT))
            drawing.add(String(10, 57, "40°C / 5bar", fontName="Helvetica", fontSize=6, fillColor=TEXT_MUTED))
            drawing.add(String(10, 15, "0°C / 0bar", fontName="Helvetica", fontSize=6, fillColor=TEXT_MUTED))

            story.append(drawing)
    else:
        story.append(Paragraph("No telemetry readings available for charting.", body_style))
    story.append(Spacer(1, 6))

    # =========================================================================
    # SECTION 9: Append-Only Chronological Security Audit Trail
    # =========================================================================
    story.append(Paragraph("9. Append-Only Chronological Security Audit Trail", h2_style))

    audit_logs = db_session.query(AuditLog).options(joinedload(AuditLog.user)).order_by(AuditLog.timestamp.desc()).limit(35).all()

    audit_headers = [
        Paragraph("Timestamp (UTC)", table_header),
        Paragraph("User / Principal", table_header),
        Paragraph("Action", table_header),
        Paragraph("Station Coords", table_header),
        Paragraph("Event Description &amp; Cryptographic Details", table_header)
    ]
    audit_rows = [audit_headers]

    for a in reversed(audit_logs):
        u_name = a.user.username if a.user else "SYSTEM"
        action_text = a.action

        color_hex = "#0F172A"
        if "VIOLATION" in action_text or "ISOLATION" in action_text or "ATTACK" in action_text:
            color_hex = "#B91C1C"
        elif "LOGIN" in action_text or "REJOIN" in action_text:
            color_hex = "#15803D"
        elif "UPDATE" in action_text or "SETPOINT" in action_text:
            color_hex = "#1E3A8A"

        act_style = ParagraphStyle('ActStyle', parent=table_text, textColor=colors.HexColor(color_hex), fontName="Helvetica-Bold")

        if hasattr(a.timestamp, "strftime"):
            ts_str = a.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(a.timestamp, (int, float)):
            ts_str = datetime.fromtimestamp(a.timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        else:
            ts_str = str(a.timestamp or '')

        audit_rows.append([
            Paragraph(html.escape(str(ts_str)), table_text),
            Paragraph(html.escape(str(u_name)), table_text),
            Paragraph(html.escape(str(action_text)), act_style),
            Paragraph(html.escape(str(a.location or "")), table_text),
            Paragraph(html.escape(str(a.details or "")), table_text)
        ])

    t_audit = Table(audit_rows, colWidths=[85, 65, 110, 85, 195])
    t_audit.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_NAVY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GREY),
    ]))
    story.append(t_audit)
    story.append(Spacer(1, 6))

    # =========================================================================
    # SECTION 10: NIST SP 800-53r5 Mandated Technical Mitigations
    # =========================================================================
    story.append(Paragraph("10. NIST SP 800-82r3 &amp; NIST SP 800-53r5 Technical Mitigation Protocols", h2_style))
    story.append(Paragraph(
        "Adhering to National Institute of Standards and Technology (NIST) Special Publication 800-82 Revision 3 "
        "(Guide to Operational Technology Security) and NIST SP 800-53 Revision 5 (Security and Privacy Controls for "
        "Information Systems and Organizations), the following technical controls are mandated across all Aegis SCADA operational nodes:",
        body_style
    ))

    mitigations = [
        "<b>NIST SP 800-53 Control AC-4 (Information Flow Enforcement &amp; Stuxnet Prevention)</b>: Enforce cross-variable "
        "correlation validation rules within the safety policy kernel. Intercept and drop any setpoint command where "
        "temperature exceeds 45.0°C when pressure is &gt;= 6.0 bar, mitigating physical centrifugal over-pressurization.",

        "<b>NIST SP 800-53 Control SC-7 (Boundary Protection &amp; Dynamic Microsegmentation)</b>: Enforce strict zone "
        "segmentation. Upon cryptographic verification failure or anomaly detection on any slave node, the master "
        "enforcer triggers immediate auto-isolation, preventing lateral movement across the ICS fieldbus.",

        "<b>NIST SP 800-53 Control SI-4 (Information System Monitoring &amp; Trust Scoring)</b>: Implement real-time continuous "
        "trust scoring across all slave nodes utilizing the 4-parameter continuous trust model (anomaly classification, "
        "HMAC integrity, violation history, and telemetry jitter stability).",

        "<b>NIST SP 800-53 Control AU-2 / AU-12 (Audit Events &amp; Cryptographic Verification)</b>: Maintain append-only "
        "audit trails linking every operator action to geospatial coordinates and authenticated operator credentials, "
        "with all field sensor payloads bound to HMAC-SHA256 signatures with floating-point canonicalization.",

        "<b>NIST SP 800-53 Control IA-2 (Identification and Authentication)</b>: Authenticate all operator sessions through "
        "salted, stretched password hashing with unique per-session CSRF token validation and rate limiting on all endpoints.",

        "<b>NIST SP 800-53 Control PE-3 (Physical Access Control &amp; Geospatial Tracking)</b>: Bind all control room logins "
        "and actuator setpoint dispatches to authenticated GPS / Cartesian plant coordinates to ensure verified physical presence."
    ]

    for m in mitigations:
        story.append(Paragraph(f"• {m}", body_style))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
