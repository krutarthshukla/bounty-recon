#!/usr/bin/env python3
"""
pdf_report.py — Convert bounty-recon markdown report to PDF.

Tries (in order):
  1. reportlab (already installed for skills)
  2. pdfkit + wkhtmltopdf
  3. markdown2pdf pip package
  4. Graceful degradation with instructions

Usage:
  python3 pdf_report.py --markdown report.md --output report.pdf
"""

import argparse, os, re, subprocess, sys

def try_reportlab(md_path, pdf_path):
    """Convert markdown to PDF using reportlab — no external binary needed."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, HRFlowable)
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
    except ImportError:
        subprocess.run(["pip3", "install", "reportlab", "-q"], capture_output=True)
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, HRFlowable)

    with open(md_path) as f:
        md = f.read()

    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                             leftMargin=2*cm, rightMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    COLORS = {
        "critical": HexColor("#CC0000"),
        "high":     HexColor("#CC6600"),
        "medium":   HexColor("#CC9900"),
        "low":      HexColor("#336699"),
        "info":     HexColor("#666666"),
    }
    style_h1 = ParagraphStyle("H1", parent=styles["Heading1"],
                               fontSize=18, textColor=HexColor("#1a1a2e"), spaceAfter=12)
    style_h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                               fontSize=14, textColor=HexColor("#16213e"), spaceAfter=8)
    style_h3 = ParagraphStyle("H3", parent=styles["Heading3"],
                               fontSize=12, textColor=HexColor("#0f3460"), spaceAfter=6)
    style_body = ParagraphStyle("Body", parent=styles["Normal"],
                                fontSize=9, leading=14, spaceAfter=6)
    style_code = ParagraphStyle("Code", parent=styles["Code"],
                                fontSize=8, backColor=HexColor("#f4f4f4"),
                                leftIndent=10, rightIndent=10, leading=12)
    style_sev = {sev: ParagraphStyle(f"SEV_{sev}", parent=styles["Normal"],
                                      fontSize=10, textColor=COLORS[sev], fontName="Helvetica-Bold")
                 for sev in COLORS}

    story = []
    in_code = False
    code_buf = []

    def flush_code():
        nonlocal in_code, code_buf
        if code_buf:
            text = "<br/>".join(l.replace("<","&lt;").replace(">","&gt;")
                                for l in code_buf)
            story.append(Paragraph(text, style_code))
            story.append(Spacer(1, 4))
        code_buf.clear()
        in_code = False

    sev_icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}

    for line in md.splitlines():
        if line.startswith("```"):
            if in_code:
                flush_code()
            else:
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue

        # Headings
        if line.startswith("# "):
            story.append(Paragraph(line[2:].replace("<","&lt;"), style_h1))
            story.append(HRFlowable(width="100%", thickness=2,
                                    color=HexColor("#1a1a2e"), spaceAfter=8))
        elif line.startswith("## "):
            story.append(Spacer(1, 8))
            story.append(Paragraph(line[3:].replace("<","&lt;"), style_h2))
        elif line.startswith("### "):
            text = line[4:].replace("<","&lt;").replace(">","&gt;")
            # Color severity headings
            sev_match = None
            for sev in ["critical","high","medium","low"]:
                if sev in text.lower():
                    sev_match = sev; break
            if sev_match:
                story.append(Paragraph(text, style_sev[sev_match]))
            else:
                story.append(Paragraph(text, style_h3))
        elif line.startswith("---"):
            story.append(HRFlowable(width="100%", thickness=0.5,
                                    color=HexColor("#cccccc"), spaceAfter=4))
        elif line.startswith("| "):
            # Table row — collect into table later (simplified: just render as text)
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if cells and not all(c.startswith("-") for c in cells):
                row_text = " | ".join(cells)
                story.append(Paragraph(row_text.replace("<","&lt;"), style_body))
        elif line.strip():
            text = line.replace("<","&lt;").replace(">","&gt;")
            # Bold **text**
            text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
            # Code `text`
            text = re.sub(r'`(.+?)`', r'<font name="Courier">\1</font>', text)
            story.append(Paragraph(text, style_body))
        else:
            story.append(Spacer(1, 4))

    if in_code:
        flush_code()

    try:
        doc.build(story)
    except Exception as e:
        # A render-time failure (bad glyph, malformed flowable) shouldn't sink the
        # whole step — return False so main() can try the pdfkit fallback.
        print(f"[!] reportlab build failed ({e}) — trying fallback", flush=True)
        return False
    return True

def try_pdfkit(md_path, pdf_path):
    """Try pdfkit (needs wkhtmltopdf)."""
    try:
        import pdfkit, markdown
        with open(md_path) as f:
            html = markdown.markdown(f.read(), extensions=["tables", "fenced_code"])
        pdfkit.from_string(f"<html><body>{html}</body></html>", pdf_path)
        return True
    except Exception:
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--markdown", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if not os.path.isfile(args.markdown):
        print(f"[!] Markdown file not found: {args.markdown}")
        sys.exit(1)

    print(f"[*] Generating PDF report...")

    # Try reportlab first (no binary needed)
    if try_reportlab(args.markdown, args.output):
        size_kb = os.path.getsize(args.output) // 1024
        print(f"[+] PDF created: {args.output} ({size_kb} KB)")
        return

    # Fallback: pdfkit
    if try_pdfkit(args.markdown, args.output):
        print(f"[+] PDF created via pdfkit: {args.output}")
        return

    print(f"[!] PDF generation failed. Install: pip3 install reportlab")
    print(f"[+] Markdown report still available: {args.markdown}")
    sys.exit(1)

if __name__ == "__main__":
    main()
