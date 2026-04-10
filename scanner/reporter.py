import os
import re
import json
from pathlib import Path
from markdown_pdf import MarkdownPdf, Section
from .schemas import ScanResult

def save_scan_result(result: ScanResult, output_dir: str = "outputs") -> tuple[str, str]:
    """
    Saves the structured JSON output and a basic PDF summary locally.
    Outputs go to '{output_dir}/scans/' and '{output_dir}/reports/'.
    """
    # Safe naming for paths
    target_safe = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', result.target)
    
    # Setup directories
    outputs_dir = Path(output_dir)
    scans_dir = outputs_dir / "scans"
    reports_dir = outputs_dir / "reports"
    
    scans_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Save JSON
    json_path = scans_dir / f"{target_safe}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result.to_json_dict(), f, indent=2)
        
    # Generate base markdown summary string
    md_text = f"# Passive Security Scan Summary: {result.target}\n\n"
    md_text += f"- **Timestamp:** {result.scan_timestamp.isoformat()}Z\n"
    md_text += f"- **Score:** {result.score} / 100\n"
    md_text += f"- **Severity:** {result.severity}\n\n"
    
    md_text += "## Key Findings\n"
    md_text += f"- HTTPS Enabled: {result.https_enabled}\n"
    md_text += f"- HTTP to HTTPS Redirect: {result.http_redirect_to_https}\n"
    md_text += f"- TLS Certificate Valid: {result.certificate_valid}\n\n"
    
    md_text += "## Recommendations\n"
    for i, rec in enumerate(result.recommendations, 1):
        md_text += f"{i}. {rec}\n"
        
    pdf_path = reports_dir / f"{target_safe}.pdf"
    pdf = MarkdownPdf(toc_level=0)
    pdf.add_section(Section(md_text))
    pdf.save(str(pdf_path))
            
    return str(json_path), str(pdf_path)
