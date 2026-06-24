import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from io import BytesIO
from jinja2 import Environment, FileSystemLoader
import os


VERDICT_COLORS = {
    "Clear": colors.HexColor("#3b82f6"),
    "Suspicious": colors.HexColor("#f59e0b"),
    "Malicious": colors.HexColor("#ef4444"),
    "Unknown": colors.HexColor("#6b7280")
}


def generate_pdf(scan_result: dict) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle("Title", parent=styles["Title"], fontSize=24, textColor=colors.HexColor("#0d1117"), spaceAfter=6)
    meta_style = ParagraphStyle("Meta", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#6b7280"), spaceAfter=12)
    heading_style = ParagraphStyle("Heading", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#161b22"), spaceBefore=16, spaceAfter=6)
    body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, leading=15)

    story.append(Paragraph("PhishSniffer", title_style))
    story.append(Paragraph(f"Analysis Report — {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", meta_style))
    story.append(Spacer(1, 0.4*cm))

    verdict = scan_result.get("verdict", "Unknown")
    verdict_color = VERDICT_COLORS.get(verdict, colors.grey)

    summary_data = [
        ["Risk Score", str(scan_result.get("risk_score", 0))],
        ["Verdict", verdict],
        ["Scan Type", scan_result.get("scan_type", "N/A")],
    ]
    summary_table = Table(summary_data, colWidths=[5*cm, 11*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("TEXTCOLOR", (1, 1), (1, 1), verdict_color),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Analyst Narrative", heading_style))
    story.append(Paragraph(scan_result.get("narrative", "N/A"), body_style))
    story.append(Spacer(1, 0.4*cm))

    iocs = scan_result.get("iocs", [])
    if iocs:
        story.append(Paragraph("Indicators of Compromise", heading_style))
        ioc_data = [["Type", "Value"]] + [[i.get("type", ""), i.get("value", "")] for i in iocs]
        ioc_table = Table(ioc_data, colWidths=[4*cm, 12*cm])
        ioc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ]))
        story.append(ioc_table)

    doc.build(story)
    return buffer.getvalue()


def generate_json(scan_result: dict) -> str:
    return json.dumps(scan_result, indent=2, default=str)


def generate_html(scan_result: dict) -> str:
    verdict = scan_result.get("verdict", "Unknown")
    verdict_colors = {
        "Clear": "#3b82f6", "Suspicious": "#f59e0b",
        "Malicious": "#ef4444", "Unknown": "#6b7280"
    }
    color = verdict_colors.get(verdict, "#6b7280")
    iocs = scan_result.get("iocs", [])
    ioc_rows = "".join(
        f"<tr><td>{i.get('type','')}</td><td style='font-family:monospace'>{i.get('value','')}</td></tr>"
        for i in iocs
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PhishSniffer Report</title>
<style>
  body {{ font-family: Inter, system-ui, sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 2rem; }}
  .card {{ background: #161b22; border: 1px solid #21262d; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.25rem; }}
  .verdict {{ color: {color}; font-weight: 700; font-size: 1.2rem; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #21262d; padding: 8px 12px; text-align: left; font-size: 0.8rem; color: #8b949e; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 0.875rem; }}
</style>
</head>
<body>
<div class="card">
  <h1>PhishSniffer</h1>
  <div style="color:#8b949e;font-size:0.85rem">Analysis Report</div>
</div>
<div class="card">
  <div style="color:#8b949e;font-size:0.75rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.5rem">Risk Score</div>
  <div style="font-size:2.5rem;font-weight:700;color:{color}">{scan_result.get('risk_score', 0)}</div>
  <div class="verdict">{verdict}</div>
</div>
<div class="card">
  <div style="color:#8b949e;font-size:0.75rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.75rem">Analyst Narrative</div>
  <p style="line-height:1.7;color:#e6edf3">{scan_result.get('narrative', 'N/A')}</p>
</div>
{f'''<div class="card">
  <div style="color:#8b949e;font-size:0.75rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.75rem">Indicators of Compromise</div>
  <table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>{ioc_rows}</tbody></table>
</div>''' if iocs else ''}
</body></html>"""