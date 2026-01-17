"""
Generate a professional penetration testing report PDF from database findings.

Usage:
    python generate_report.py <target_uuid>
    python generate_report.py --list  # List all targets

Requirements:
    pip install reportlab
"""

import sys
import json
from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, ListFlowable, ListItem, HRFlowable
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
except ImportError:
    print("Error: reportlab is required for PDF generation.")
    print("Install it with: pip install reportlab")
    sys.exit(1)

from database import get_db


# Severity colors
SEVERITY_COLORS = {
    "critical": colors.Color(0.8, 0, 0),      # Dark red
    "high": colors.Color(1, 0.3, 0),          # Orange-red
    "medium": colors.Color(1, 0.6, 0),        # Orange
    "low": colors.Color(0.2, 0.6, 0.2),       # Green
    "info": colors.Color(0.3, 0.5, 0.8),      # Blue
}

SEVERITY_BG_COLORS = {
    "critical": colors.Color(1, 0.9, 0.9),
    "high": colors.Color(1, 0.95, 0.9),
    "medium": colors.Color(1, 1, 0.9),
    "low": colors.Color(0.9, 1, 0.9),
    "info": colors.Color(0.9, 0.95, 1),
}


def create_styles():
    """Create custom paragraph styles for the report."""
    styles = getSampleStyleSheet()

    # Title style
    styles.add(ParagraphStyle(
        name='ReportTitle',
        parent=styles['Heading1'],
        fontSize=28,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.Color(0.1, 0.1, 0.3),
    ))

    # Section header style
    styles.add(ParagraphStyle(
        name='SectionHeader',
        parent=styles['Heading1'],
        fontSize=18,
        spaceBefore=20,
        spaceAfter=10,
        textColor=colors.Color(0.1, 0.1, 0.3),
        borderPadding=5,
    ))

    # Subsection style
    styles.add(ParagraphStyle(
        name='SubSection',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=15,
        spaceAfter=8,
        textColor=colors.Color(0.2, 0.2, 0.4),
    ))

    # Finding title style
    styles.add(ParagraphStyle(
        name='FindingTitle',
        parent=styles['Heading3'],
        fontSize=12,
        spaceBefore=10,
        spaceAfter=5,
        textColor=colors.Color(0.2, 0.2, 0.2),
    ))

    # Body text style - customize the existing BodyText
    styles['BodyText'].fontSize = 10
    styles['BodyText'].spaceAfter = 8
    styles['BodyText'].alignment = TA_JUSTIFY

    # Evidence style (monospace-like)
    styles.add(ParagraphStyle(
        name='EvidenceText',
        parent=styles['Normal'],
        fontSize=9,
        fontName='Courier',
        backColor=colors.Color(0.95, 0.95, 0.95),
        borderPadding=8,
        spaceAfter=8,
    ))

    return styles


def create_cover_page(story, styles, target_data):
    """Create the report cover page."""
    story.append(Spacer(1, 2 * inch))

    story.append(Paragraph("PENETRATION TESTING REPORT", styles['ReportTitle']))

    story.append(Spacer(1, 0.5 * inch))

    # Target info
    target = target_data.get('target', {})
    target_name = target.get('name', 'Unknown Target')

    story.append(Paragraph(f"<b>Target:</b> {target_name}", styles['BodyText']))
    story.append(Paragraph(f"<b>Type:</b> {target.get('type', 'N/A')}", styles['BodyText']))
    story.append(Paragraph(f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['BodyText']))

    story.append(Spacer(1, 1 * inch))

    # Findings summary
    findings = target_data.get('findings', {})
    summary_data = [
        ['Severity', 'Count'],
        ['Critical', str(len(findings.get('critical', [])))],
        ['High', str(len(findings.get('high', [])))],
        ['Medium', str(len(findings.get('medium', [])))],
        ['Low', str(len(findings.get('low', [])))],
        ['Informational', str(len(findings.get('info', [])))],
    ]

    summary_table = Table(summary_data, colWidths=[2 * inch, 1.5 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.1, 0.1, 0.3)),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, 1), SEVERITY_BG_COLORS['critical']),
        ('BACKGROUND', (0, 2), (-1, 2), SEVERITY_BG_COLORS['high']),
        ('BACKGROUND', (0, 3), (-1, 3), SEVERITY_BG_COLORS['medium']),
        ('BACKGROUND', (0, 4), (-1, 4), SEVERITY_BG_COLORS['low']),
        ('BACKGROUND', (0, 5), (-1, 5), SEVERITY_BG_COLORS['info']),
        ('GRID', (0, 0), (-1, -1), 1, colors.Color(0.7, 0.7, 0.7)),
    ]))

    story.append(summary_table)

    story.append(PageBreak())


def create_executive_summary(story, styles, target_data):
    """Create the executive summary section."""
    story.append(Paragraph("1. EXECUTIVE SUMMARY", styles['SectionHeader']))

    story.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.1, 0.1, 0.3)))

    findings = target_data.get('findings', {})
    total_findings = sum(len(f) for f in findings.values())
    critical_count = len(findings.get('critical', []))
    high_count = len(findings.get('high', []))

    target = target_data.get('target', {})

    summary_text = f"""
    This penetration testing report presents the findings from the security assessment
    conducted on <b>{target.get('name', 'the target')}</b>. The assessment utilized
    automated reconnaissance tools to identify potential security vulnerabilities
    and misconfigurations.
    """
    story.append(Paragraph(summary_text, styles['BodyText']))

    story.append(Spacer(1, 0.2 * inch))

    results_text = f"""
    <b>Key Findings:</b><br/>
    A total of <b>{total_findings} findings</b> were identified during this assessment,
    including <b>{critical_count} critical</b> and <b>{high_count} high</b> severity issues
    that require immediate attention.
    """
    story.append(Paragraph(results_text, styles['BodyText']))

    # Risk assessment
    if critical_count > 0 or high_count > 2:
        risk_level = "HIGH"
        risk_color = SEVERITY_COLORS['high']
    elif high_count > 0 or len(findings.get('medium', [])) > 3:
        risk_level = "MEDIUM"
        risk_color = SEVERITY_COLORS['medium']
    else:
        risk_level = "LOW"
        risk_color = SEVERITY_COLORS['low']

    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(f"<b>Overall Risk Assessment:</b> <font color='{risk_color}'>{risk_level}</font>", styles['BodyText']))

    story.append(Spacer(1, 0.3 * inch))


def create_scope_section(story, styles, target_data):
    """Create the scope section."""
    story.append(Paragraph("2. SCOPE OF ASSESSMENT", styles['SectionHeader']))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.1, 0.1, 0.3)))

    target = target_data.get('target', {})

    story.append(Paragraph("<b>Target Information:</b>", styles['SubSection']))

    scope_data = [
        ['Property', 'Value'],
        ['Target Name', target.get('name', 'N/A')],
        ['Target Type', target.get('type', 'N/A')],
        ['Assessment Date', target.get('created_at', 'N/A')[:10] if target.get('created_at') else 'N/A'],
    ]

    scope_table = Table(scope_data, colWidths=[2 * inch, 4 * inch])
    scope_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.9, 0.9, 0.9)),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.Color(0.7, 0.7, 0.7)),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(scope_table)

    story.append(Spacer(1, 0.2 * inch))

    # Tools used
    story.append(Paragraph("<b>Tools Utilized:</b>", styles['SubSection']))
    tools = [
        "WHOIS - Domain registration lookup",
        "Subfinder - Subdomain enumeration",
        "Nmap - Port scanning and service detection",
        "Httpx - HTTP service probing",
        "Gobuster - Directory and file brute-forcing",
    ]
    for tool in tools:
        story.append(Paragraph(f"  - {tool}", styles['BodyText']))

    story.append(Spacer(1, 0.3 * inch))


def create_findings_section(story, styles, target_data):
    """Create the detailed findings section."""
    story.append(PageBreak())
    story.append(Paragraph("3. DETAILED FINDINGS", styles['SectionHeader']))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.1, 0.1, 0.3)))

    findings = target_data.get('findings', {})
    finding_number = 1

    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        severity_findings = findings.get(severity, [])
        if not severity_findings:
            continue

        severity_display = severity.upper() if severity != 'info' else 'INFORMATIONAL'
        story.append(Paragraph(f"3.{finding_number}. {severity_display} SEVERITY FINDINGS", styles['SubSection']))

        for finding in severity_findings:
            # Finding title with severity indicator
            color = SEVERITY_COLORS.get(severity, colors.black)

            title_table = Table(
                [[Paragraph(f"<font color='white'>{severity.upper()}</font>", styles['BodyText']),
                  Paragraph(f"<b>{finding.get('title', 'Untitled Finding')}</b>", styles['FindingTitle'])]],
                colWidths=[0.8 * inch, 5.2 * inch]
            )
            title_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, 0), color),
                ('ALIGN', (0, 0), (0, 0), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(title_table)

            # Finding details
            details = [
                ('Tool', finding.get('tool', 'N/A')),
                ('Affected Asset', finding.get('affected_asset', 'N/A')),
                ('Discovered', finding.get('found_at', 'N/A')[:19] if finding.get('found_at') else 'N/A'),
            ]

            for label, value in details:
                story.append(Paragraph(f"<b>{label}:</b> {value}", styles['BodyText']))

            # Description
            if finding.get('description'):
                story.append(Spacer(1, 0.1 * inch))
                story.append(Paragraph("<b>Description:</b>", styles['BodyText']))
                story.append(Paragraph(finding['description'], styles['BodyText']))

            # Evidence
            if finding.get('evidence'):
                story.append(Spacer(1, 0.1 * inch))
                story.append(Paragraph("<b>Evidence:</b>", styles['BodyText']))
                story.append(Paragraph(finding['evidence'], styles['EvidenceText']))

            # Recommendation
            if finding.get('recommendation'):
                story.append(Spacer(1, 0.1 * inch))
                story.append(Paragraph("<b>Recommendation:</b>", styles['BodyText']))
                story.append(Paragraph(finding['recommendation'], styles['BodyText']))

            story.append(Spacer(1, 0.3 * inch))

        finding_number += 1


def create_reconnaissance_section(story, styles, target_data):
    """Create the reconnaissance data section."""
    story.append(PageBreak())
    story.append(Paragraph("4. RECONNAISSANCE DATA", styles['SectionHeader']))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.1, 0.1, 0.3)))

    # Subdomains
    subdomains = target_data.get('subdomains', [])
    if subdomains:
        story.append(Paragraph("4.1. Discovered Subdomains", styles['SubSection']))
        subdomain_data = [['Subdomain', 'Source', 'Discovered']]
        for sd in subdomains[:20]:  # Limit to 20
            subdomain_data.append([
                sd.get('subdomain', 'N/A'),
                sd.get('source', 'N/A'),
                sd.get('scanned_at', 'N/A')[:10] if sd.get('scanned_at') else 'N/A'
            ])

        if len(subdomains) > 20:
            subdomain_data.append([f"... and {len(subdomains) - 20} more", '', ''])

        sub_table = Table(subdomain_data, colWidths=[3 * inch, 1.5 * inch, 1.5 * inch])
        sub_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.9, 0.9, 0.9)),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.Color(0.7, 0.7, 0.7)),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(sub_table)
        story.append(Spacer(1, 0.3 * inch))

    # Open Ports
    ports = [p for p in target_data.get('ports', []) if p.get('state') == 'open']
    if ports:
        story.append(Paragraph("4.2. Open Ports", styles['SubSection']))
        port_data = [['Host', 'Port', 'Service', 'Version']]
        for port in ports[:20]:
            port_data.append([
                port.get('host', 'N/A'),
                f"{port.get('port', 'N/A')}/{port.get('protocol', 'tcp')}",
                port.get('service', 'N/A'),
                port.get('version', 'N/A') or 'N/A'
            ])

        port_table = Table(port_data, colWidths=[2.5 * inch, 1 * inch, 1.2 * inch, 1.8 * inch])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.9, 0.9, 0.9)),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.Color(0.7, 0.7, 0.7)),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(port_table)
        story.append(Spacer(1, 0.3 * inch))

    # HTTP Services
    http_services = target_data.get('http_services', [])
    if http_services:
        story.append(Paragraph("4.3. HTTP Services", styles['SubSection']))
        http_data = [['URL', 'Status', 'Title']]
        for svc in http_services[:15]:
            http_data.append([
                svc.get('url', 'N/A')[:50],
                str(svc.get('status_code', 'N/A')),
                (svc.get('title', 'N/A') or 'N/A')[:30]
            ])

        http_table = Table(http_data, colWidths=[3 * inch, 0.8 * inch, 2.2 * inch])
        http_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.9, 0.9, 0.9)),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.Color(0.7, 0.7, 0.7)),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(http_table)


def create_conclusion_section(story, styles, target_data):
    """Create the conclusion section."""
    story.append(PageBreak())
    story.append(Paragraph("5. CONCLUSION", styles['SectionHeader']))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.1, 0.1, 0.3)))

    findings = target_data.get('findings', {})
    critical_count = len(findings.get('critical', []))
    high_count = len(findings.get('high', []))

    conclusion_text = """
    This penetration testing assessment has identified several security issues
    that should be addressed to improve the overall security posture of the target environment.
    """
    story.append(Paragraph(conclusion_text, styles['BodyText']))

    if critical_count > 0:
        story.append(Paragraph(
            f"<b>Immediate Action Required:</b> {critical_count} critical severity finding(s) "
            "require immediate remediation to prevent potential compromise.",
            styles['BodyText']
        ))

    if high_count > 0:
        story.append(Paragraph(
            f"<b>High Priority:</b> {high_count} high severity finding(s) should be addressed "
            "as soon as possible to reduce significant security risk.",
            styles['BodyText']
        ))

    story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph("<b>Recommended Next Steps:</b>", styles['SubSection']))
    next_steps = [
        "Address all critical and high severity findings immediately",
        "Implement recommended fixes for medium severity findings within 30 days",
        "Review and address low severity findings during regular maintenance",
        "Schedule a follow-up assessment to verify remediation effectiveness",
        "Implement continuous security monitoring for the target environment",
    ]
    for step in next_steps:
        story.append(Paragraph(f"  - {step}", styles['BodyText']))

    story.append(Spacer(1, 0.5 * inch))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.Color(0.1, 0.1, 0.3)))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(
        f"<i>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
        "using MCP Security Tools</i>",
        styles['BodyText']
    ))


def generate_report(target_uuid: str, output_path: str = None):
    """Generate a PDF report for the given target."""

    db = get_db()

    # Get all data for the target
    target_data = db.get_full_report_data(target_uuid)

    if not target_data or not target_data.get('target'):
        print(f"Error: Target with UUID '{target_uuid}' not found.")
        return None

    target = target_data['target']
    target_name = target.get('name', 'unknown')

    # Determine output path
    if not output_path:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f"pentest_report_{target_name}_{timestamp}.pdf"

    # Create PDF document
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    # Create styles
    styles = create_styles()

    # Build story (content)
    story = []

    create_cover_page(story, styles, target_data)
    create_executive_summary(story, styles, target_data)
    create_scope_section(story, styles, target_data)
    create_findings_section(story, styles, target_data)
    create_reconnaissance_section(story, styles, target_data)
    create_conclusion_section(story, styles, target_data)

    # Build PDF
    doc.build(story)

    print(f"Report generated: {output_path}")
    return output_path


def list_targets():
    """List all available targets."""
    db = get_db()
    targets = db.get_all_targets()

    if not targets:
        print("No targets found in database.")
        print("Run 'python populate_simulation_data.py' to create sample data.")
        return

    print("\nAvailable Targets:")
    print("-" * 80)
    print(f"{'UUID':<40} {'Name':<25} {'Type':<10} {'Created':<20}")
    print("-" * 80)

    for target in targets:
        created = target.get('created_at', '')[:19] if target.get('created_at') else 'N/A'
        print(f"{target['uuid']:<40} {target['name']:<25} {target['type']:<10} {created:<20}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python generate_report.py <target_uuid>  - Generate report for target")
        print("  python generate_report.py --list         - List all targets")
        sys.exit(1)

    if sys.argv[1] == '--list':
        list_targets()
    else:
        target_uuid = sys.argv[1]
        output_path = sys.argv[2] if len(sys.argv) > 2 else None
        generate_report(target_uuid, output_path)


if __name__ == "__main__":
    main()
