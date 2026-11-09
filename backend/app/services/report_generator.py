"""PDF report generation for alerts and investigations.

Creates professional PDF reports from alert data with:
- Alert summary and metadata
- Evidence sources with links
- Correlation timelines
- Recommended actions
- Exportable for compliance and case handoffs
"""

import io
from datetime import datetime

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

from app.models.alert import Alert


def generate_alert_pdf(alert: Alert) -> bytes:
    """Generate a PDF report for a single alert.

    Args:
        alert: The alert object to generate a report for.

    Returns:
        PDF content as bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=LETTER, rightMargin=0.6*inch, leftMargin=0.6*inch, topMargin=0.6*inch, bottomMargin=0.6*inch)
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=HexColor("#1a1a2e"),
        spaceAfter=6,
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "CustomSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=HexColor("#444444"),
        alignment=TA_CENTER,
        spaceAfter=12,
    )
    section_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading1"],
        fontSize=14,
        textColor=HexColor("#00D4FF"),
        spaceAfter=6,
        spaceBefore=12,
    )
    body_style = ParagraphStyle(
        "BodyText2",
        parent=styles["Normal"],
        fontSize=9,
        textColor=HexColor("#333333"),
        leading=13,
        spaceAfter=6,
    )
    meta_style = ParagraphStyle(
        "MetaText",
        parent=styles["Normal"],
        fontSize=8,
        textColor=HexColor("#666666"),
        leading=10,
        spaceAfter=3,
    )

    elements = []

    # Header block
    elements.append(Paragraph("RYNEX THREAT INTELLIGENCE PLATFORM", title_style))
    elements.append(Paragraph("PDF Alert Report", subtitle_style))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", meta_style))
    elements.append(Spacer(1, 12))

    # Alert metadata table
    meta_data = [
        ["Alert ID", str(alert.id)],
        ["Title", alert.title],
        ["Category", alert.category or "—"],
        ["Severity", alert.severity.upper()],
        ["Confidence", f"{alert.confidence:.0%}"],
        ["Status", alert.status.upper()],
        ["Detected At", alert.detected_at.strftime("%Y-%m-%d %H:%M UTC") if alert.detected_at else "—"],
        ["First Published", alert.first_published_at.strftime("%Y-%m-%d %H:%M UTC") if alert.first_published_at else "—"],
    ]

    meta_table = Table(meta_data, colWidths=[1.5*inch, 4*inch])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), HexColor("#f0f4f8")),
                ("TEXTCOLOR", (0, 0), (-1, -1), black),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [white, HexColor("#fafafa")]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    elements.append(meta_table)
    elements.append(Spacer(1, 12))

    # Evidence sources
    if alert.evidence_sources:
        elements.append(Paragraph("Evidence Sources", section_style))
        elements.append(Spacer(1, 6))

        source_data = [["Source", "URL", "Published"]]
        for src in alert.evidence_sources:
            source_data.append([
                src.get("source_slug", "—"),
                src.get("url", "—"),
                src.get("published_at", "—"),
            ])

        source_table = Table(source_data, colWidths=[1.2*inch, 2.8*inch, 1.5*inch])
        source_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), HexColor("#00D4FF")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), white),
                    ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [white, HexColor("#fafafa")]),
                ]
            )
        )
        elements.append(source_table)
        elements.append(Spacer(1, 12))

    # Description
    if alert.description:
        elements.append(Paragraph("Alert Description", section_style))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(alert.description, body_style))
        elements.append(Spacer(1, 12))

    # Recommended action
    if alert.recommended_action:
        elements.append(Paragraph("Recommended Action", section_style))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(alert.recommended_action, body_style))
        elements.append(Spacer(1, 12))

    # Correlation info
    elements.append(Paragraph("Correlation & Investigation", section_style))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        f"This alert is correlated with {len(alert.evidence_sources or [])} evidence "
        f"record(s) from {len(set(str(s.get('source_slug', '')) for s in (alert.evidence_sources or [])))} unique source(s).",
        body_style
    ))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        f"Fingerprint: {alert.fingerprint[:16]}...{alert.fingerprint[-16:] if len(alert.fingerprint) > 32 else alert.fingerprint}",
        body_style
    ))
    elements.append(Spacer(1, 12))

    # Footer
    elements.append(PageBreak())
    elements.append(Paragraph("RYNEX RTIP — Confidential", meta_style))
    elements.append(Paragraph(
        f"Report generated by RTIP v0.1.0 | Confidence engine: deterministic | "
        f"For internal use only | Do not distribute without verification.",
        meta_style
    ))

    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes