"""
PDF forensic report generator using ReportLab.

Produces a multi-section PDF suitable for audit / legal submission:
  1. Executive Summary
  2. Access Decision Breakdown
  3. Timeline (tabular)
  4. Detected Anomalies
  5. Hash Chain Verification Proof
"""

import io
from datetime import datetime, timezone
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _styles():
    ss = getSampleStyleSheet()
    ss.add(
        ParagraphStyle(
            "SectionTitle",
            parent=ss["Heading2"],
            textColor=colors.HexColor("#1a3a5c"),
            spaceBefore=14,
            spaceAfter=4,
        )
    )
    ss.add(
        ParagraphStyle(
            "SmallCode",
            parent=ss["Code"],
            fontSize=7,
            leading=9,
        )
    )
    return ss


def _header_table_style():
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a3a5c")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]
    )


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _section_executive_summary(records, anomalies, chain_ok, styles):
    """Return list of flowables for the executive summary section."""
    flowables = []
    total = len(records)
    allowed = sum(1 for r in records if r.get("decision") == "ALLOW")
    denied = total - allowed
    high_risk = sum(1 for r in records if int(r.get("risk_score", 0)) >= 70)
    anom_count = len(anomalies)
    chain_status = "VERIFIED ✓" if chain_ok else "BROKEN ✗"

    flowables.append(Paragraph("Executive Summary", styles["SectionTitle"]))
    flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a3a5c")))
    flowables.append(Spacer(1, 0.3 * cm))

    summary_text = (
        f"This report covers <b>{total}</b> access decisions recorded by the "
        f"ZTForensics Zero Trust Gateway. Of these, <b>{allowed}</b> were allowed "
        f"and <b>{denied}</b> were denied. <b>{high_risk}</b> event(s) carried a "
        f"risk score ≥ 70. Anomaly detection identified <b>{anom_count}</b> "
        f"suspicious pattern(s). Hash chain integrity: <b>{chain_status}</b>."
    )
    flowables.append(Paragraph(summary_text, styles["Normal"]))
    flowables.append(Spacer(1, 0.4 * cm))

    data = [
        ["Metric", "Value"],
        ["Total Requests", str(total)],
        ["Allowed", f"{allowed} ({100 * allowed // total if total else 0}%)"],
        ["Denied", f"{denied} ({100 * denied // total if total else 0}%)"],
        ["High Risk Events (≥70)", str(high_risk)],
        ["Anomalies Detected", str(anom_count)],
        ["Hash Chain", chain_status],
        ["Report Generated (UTC)", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")],
    ]
    tbl = Table(data, colWidths=[9 * cm, 9 * cm])
    tbl.setStyle(_header_table_style())
    flowables.append(tbl)
    return flowables


def _section_access_decisions(records, styles):
    """Return flowables for access decision breakdown."""
    flowables = []
    flowables.append(Paragraph("Access Decision Breakdown", styles["SectionTitle"]))
    flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a3a5c")))
    flowables.append(Spacer(1, 0.3 * cm))

    headers = ["#", "Timestamp", "User", "Resource", "Action", "Decision", "Risk"]
    rows = [headers]
    for i, r in enumerate(records, 1):
        ts = str(r.get("timestamp", ""))[:19]
        user = str(r.get("user_name") or r.get("user", ""))[:12]
        resource = str(r.get("resource", ""))[:22]
        action = str(r.get("action", ""))[:8]
        decision = str(r.get("decision", ""))
        risk = str(r.get("risk_score", 0))
        rows.append([str(i), ts, user, resource, action, decision, risk])

    col_widths = [1 * cm, 4.2 * cm, 2.5 * cm, 4.5 * cm, 1.8 * cm, 2 * cm, 1.5 * cm]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    style = _header_table_style()
    # Colour denied rows red
    for i, r in enumerate(records, 1):
        if r.get("decision") == "DENY":
            style.add("TEXTCOLOR", (5, i), (5, i), colors.red)
    tbl.setStyle(style)
    flowables.append(tbl)
    return flowables


def _section_anomalies(anomalies, styles):
    """Return flowables for anomaly listing."""
    flowables = []
    flowables.append(Paragraph("Detected Anomalies", styles["SectionTitle"]))
    flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a3a5c")))
    flowables.append(Spacer(1, 0.3 * cm))

    if not anomalies:
        flowables.append(Paragraph("No anomalies detected.", styles["Normal"]))
        return flowables

    headers = ["Type", "Subject", "Count", "Confidence", "Severity", "Timestamp"]
    rows = [headers]
    for a in anomalies:
        subject = a.get("user") or a.get("ip_address", "")
        rows.append(
            [
                str(a.get("type", "")),
                str(subject)[:20],
                str(a.get("count", "")),
                f"{a.get('confidence', 0):.0%}",
                str(a.get("severity", "")),
                str(a.get("timestamp", ""))[:19],
            ]
        )

    col_widths = [4.5 * cm, 3.5 * cm, 1.5 * cm, 2.2 * cm, 2 * cm, 3.8 * cm]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    style = _header_table_style()
    severity_colors = {"HIGH": colors.red, "MEDIUM": colors.orange, "LOW": colors.green}
    for i, a in enumerate(anomalies, 1):
        col = severity_colors.get(a.get("severity", ""), colors.black)
        style.add("TEXTCOLOR", (4, i), (4, i), col)
    tbl.setStyle(style)
    flowables.append(tbl)
    return flowables


def _section_hash_chain(records, styles):
    """Return flowables for hash chain verification proof."""
    flowables = []
    flowables.append(Paragraph("Hash Chain Verification Proof", styles["SectionTitle"]))
    flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a3a5c")))
    flowables.append(Spacer(1, 0.3 * cm))

    expected_prev = "0"
    chain_valid = True

    headers = ["#", "Record Hash (first 16)", "Prev Hash (first 16)", "Status"]
    rows = [headers]
    for i, r in enumerate(records, 1):
        prev = r.get("previous_hash", "")
        rec_hash = r.get("record_hash", "")
        ok = prev == expected_prev
        if not ok:
            chain_valid = False
        status = "✓ OK" if ok else "✗ BROKEN"
        rows.append(
            [
                str(i),
                rec_hash[:16] + "…" if len(rec_hash) > 16 else rec_hash,
                prev[:16] + "…" if len(prev) > 16 else prev,
                status,
            ]
        )
        expected_prev = rec_hash

    col_widths = [1 * cm, 6.5 * cm, 6.5 * cm, 3.5 * cm]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    style = _header_table_style()
    for i, r in enumerate(records, 1):
        prev = r.get("previous_hash", "")
        ok = prev == ("0" if i == 1 else records[i - 2].get("record_hash", ""))
        if not ok:
            style.add("TEXTCOLOR", (3, i), (3, i), colors.red)
        else:
            style.add("TEXTCOLOR", (3, i), (3, i), colors.green)
    tbl.setStyle(style)
    flowables.append(tbl)

    flowables.append(Spacer(1, 0.3 * cm))
    verdict = "✓ CHAIN VALID — No tampering detected." if chain_valid else "✗ CHAIN BROKEN — Tampering detected!"
    verdict_color = colors.green if chain_valid else colors.red
    verdict_style = ParagraphStyle(
        "Verdict", parent=styles["Normal"], textColor=verdict_color, fontSize=11, leading=14
    )
    flowables.append(Paragraph(f"<b>{verdict}</b>", verdict_style))
    return flowables


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_pdf_report(
    records: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    chain_ok: bool = True,
) -> bytes:
    """
    Generate a PDF forensic report and return it as bytes.

    Args:
        records:   Evidence records from the database.
        timeline:  Pre-computed timeline buckets (from timeline_analyzer).
        anomalies: Pre-computed anomaly list (from anomaly_detector).
        chain_ok:  Boolean result of hash chain verification.

    Returns:
        Raw PDF bytes suitable for streaming as a HTTP response.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2 * cm,
        title="ZTForensics Forensic Evidence Report",
        author="ZTForensics Gateway",
    )

    styles = _styles()
    story = []

    # Title
    story.append(Paragraph("ZTForensics — Forensic Evidence Report", styles["Title"]))
    story.append(
        Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.6 * cm))

    # Sections
    story.extend(_section_executive_summary(records, anomalies, chain_ok, styles))
    story.append(Spacer(1, 0.5 * cm))
    story.extend(_section_access_decisions(records, styles))
    story.append(Spacer(1, 0.5 * cm))
    story.extend(_section_anomalies(anomalies, styles))
    story.append(Spacer(1, 0.5 * cm))
    story.extend(_section_hash_chain(records, styles))

    # Timeline summary table
    if timeline:
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph("Access Timeline Summary", styles["SectionTitle"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a3a5c")))
        story.append(Spacer(1, 0.3 * cm))
        tl_headers = ["Period", "Total", "Allowed", "Denied", "Avg Risk", "High Risk"]
        tl_rows = [tl_headers]
        for t in timeline:
            tl_rows.append(
                [
                    t.get("period", ""),
                    str(t.get("total_requests", 0)),
                    str(t.get("allowed", 0)),
                    str(t.get("denied", 0)),
                    str(t.get("avg_risk_score", 0)),
                    str(t.get("high_risk_events", 0)),
                ]
            )
        tl_tbl = Table(
            tl_rows,
            colWidths=[5 * cm, 2 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm],
            repeatRows=1,
        )
        tl_tbl.setStyle(_header_table_style())
        story.append(tl_tbl)

    # Footer note
    story.append(Spacer(1, 0.8 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(
        Paragraph(
            "This report was auto-generated by ZTForensics. "
            "Hash-chain evidence is cryptographically verifiable and suitable for "
            "audit, regulatory compliance, and legal proceedings.",
            styles["Italic"],
        )
    )

    doc.build(story)
    buf.seek(0)
    return buf.getvalue()
