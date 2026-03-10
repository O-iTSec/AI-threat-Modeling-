"""PDF threat model report generation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITY_COLORS = {
    "critical": HexColor("#DC2626"),
    "high": HexColor("#EA580C"),
    "medium": HexColor("#CA8A04"),
    "low": HexColor("#2563EB"),
    "info": HexColor("#6B7280"),
}


class PDFReporter:
    """Generate a formatted PDF threat model report."""

    def generate(self, scored: dict[str, Any], output_path: Path) -> Path:
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("AI Threat Model Report", styles["Title"]))
        story.append(Spacer(1, 0.5 * cm))

        summary = scored.get("summary", {})
        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        story.append(
            Paragraph(
                f"Total threats identified: <b>{summary.get('total', 0)}</b> &nbsp;|&nbsp; "
                f"Highest risk score: <b>{summary.get('highest_risk', 0)}</b>",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))

        by_sev = summary.get("by_severity", {})
        if by_sev:
            sev_data = [["Severity", "Count"]]
            for sev in ("critical", "high", "medium", "low", "info"):
                if sev in by_sev:
                    sev_data.append([sev.capitalize(), str(by_sev[sev])])
            sev_table = Table(sev_data, colWidths=[6 * cm, 4 * cm])
            sev_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1F2937")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#FFFFFF")),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#D1D5DB")),
                        ("ALIGN", (1, 0), (1, -1), "CENTER"),
                    ]
                )
            )
            story.append(sev_table)
            story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Threat Details", styles["Heading2"]))
        for entry in scored.get("threats", []):
            threat = entry.get("threat", entry)
            title = threat.get("title", "Untitled")
            sev = entry.get("severity", "info")
            score = entry.get("risk_score", 0)
            desc = threat.get("description", "")

            color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
            header_style = ParagraphStyle(
                "threat_header",
                parent=styles["Heading3"],
                textColor=color,
            )
            story.append(Paragraph(f"{title}  [{sev.upper()}]  (score: {score})", header_style))
            story.append(Paragraph(desc, styles["Normal"]))

            mitre = entry.get("mitre", {})
            techniques = mitre.get("techniques", [])
            if techniques:
                tech_text = ", ".join(f"{t['id']} ({t['name']})" for t in techniques)
                story.append(Paragraph(f"<i>MITRE ATT&CK:</i> {tech_text}", styles["Normal"]))

            story.append(Spacer(1, 0.3 * cm))

        doc.build(story)
        return output_path
