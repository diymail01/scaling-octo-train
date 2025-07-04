from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import os
from datetime import datetime

def generate_pdf_report(compliance_data, category, ip_address):
    """
    Generate a PDF report from compliance data
    
    Args:
        compliance_data (list): List of compliance check results
        category (str): Category of the scan (e.g., 'UTM', 'SSH')
        ip_address (str): Target IP address
        
    Returns:
        str: Path to the generated PDF file
    """
    # Create reports directory if it doesn't exist
    os.makedirs("reports", exist_ok=True)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{category}_Compliance_{ip_address}_{timestamp}.pdf"
    
    # Create document
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=72, leftMargin=72,
        topMargin=72, bottomMargin=18
    )
    
    # Get styles
    styles = getSampleStyleSheet()
    elements = []
    
    # Add title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=14,
        alignment=1  # Center aligned
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=24,
        alignment=1  # Center aligned
    )
    
    elements.append(Paragraph(f"{category} Compliance Report", title_style))
    elements.append(Paragraph(f"Target: {ip_address}", subtitle_style))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 0.25 * inch))
    
    # Prepare table data
    table_data = [
        ['Sr. No.', 'Parameter', 'Status', 'Threat Level', 'Details']
    ]
    
    # Add compliance items
    for i, item in enumerate(compliance_data, 1):
        table_data.append([
            str(i),
            item['parameter'],
            item['status'],
            item['threat_level'],
            item.get('details', '')[:100] + ('...' if len(item.get('details', '')) > 100 else '')
        ])
    
    # Create table
    table = Table(table_data, colWidths=[0.5*inch, 2*inch, 1*inch, 1*inch, 2.5*inch])
    
    # Add style to table
    table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4472C4')),  # Header row
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#D9E1F2')),  # Alternate row color
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ])
    
    # Add conditional formatting for status
    for i, row in enumerate(compliance_data, 1):
        if row['status'] == 'Compliant':
            table_style.add('TEXTCOLOR', (2, i), (2, i), colors.green)
        elif row['status'] == 'Non-Compliant':
            table_style.add('TEXTCOLOR', (2, i), (2, i), colors.red)
        
        # Color code threat levels
        if row['threat_level'] == 'High':
            table_style.add('TEXTCOLOR', (3, i), (3, i), colors.red)
        elif row['threat_level'] == 'Medium':
            table_style.add('TEXTCOLOR', (3, i), (3, i), colors.orange)
        elif row['threat_level'] == 'Info':
            table_style.add('TEXTCOLOR', (3, i), (3, i), colors.blue)
    
    table.setStyle(table_style)
    elements.append(table)
    
    # Add summary
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph("Summary", styles['Heading2']))
    
    total_checks = len(compliance_data)
    compliant = sum(1 for item in compliance_data if item['status'] == 'Compliant')
    non_compliant = total_checks - compliant
    
    summary_text = f"""
    <para>Total Checks: {total_checks}<br/>
    Compliant: <font color='green'>{compliant}</font><br/>
    Non-Compliant: <font color='red'>{non_compliant}</font><br/>
    Compliance Rate: {compliant/total_checks*100:.1f}%</para>
    """
    
    elements.append(Paragraph(summary_text, styles['Normal']))
    
    # Add footer
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph("Generated by Perimeter Network Compliance Audit Tool", 
                            ParagraphStyle('Footer', parent=styles['Italic'], fontSize=8, alignment=1)))
    
    # Build PDF
    doc.build(elements)
    
    return filename
