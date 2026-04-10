import os
import re
import json
from pathlib import Path
from markdown_pdf import MarkdownPdf, Section
from .schemas import ScanResult

def render_pdf(markdown_content: str, pdf_path: str) -> str:
    """
    Abstracted PDF rendering engine.
    This enables future refactors (e.g. HTML rendering) without altering core logic.
    """
    pdf = MarkdownPdf(toc_level=0)
    pdf.add_section(Section(markdown_content))
    pdf.save(str(pdf_path))
    return str(pdf_path)

def build_premium_report(result: ScanResult, ai_content: str | None = None) -> str:
    """
    Constructs the V1.5 premium structured Markdown report deterministically.
    Ensures safe formatting, bulleted technical notes, and mandatory disclaimers.
    """
    # 1. Premium Brand Header
    md_text = f"# Cyberburgs\n"
    md_text += f"## Passive Website Security Posture Report\n\n"
    md_text += f"---\n\n"
    md_text += f"> **Target:** `{result.target}`  \n"
    md_text += f"> **Generated:** `{result.scan_timestamp.isoformat()}Z`  \n"
    md_text += f"> **Security Score:** `{result.score} / 100`  \n"
    md_text += f"> **Overall Rating:** `{result.severity}`\n\n"
    md_text += f"---\n\n"
    
    # 2. Main analytical body
    if ai_content:
        # Prevent markdown conflicts by inserting cleanly
        md_text += ai_content.strip() + "\n\n"
    else:
        # V1.5 Fallback block
        md_text += "## Executive Summary\n"
        md_text += "Baseline mechanical checks successfully concluded locally. This is a structured fallback report as AI processing was either disabled or unavailable.\n\n"
        md_text += "## Key Findings\n"
        md_text += f"- HTTPS Enabled: {result.https_enabled}\n"
        md_text += f"- HTTP to HTTPS Redirect: {result.http_redirect_to_https}\n"
        md_text += f"- TLS Certificate Valid: {result.certificate_valid}\n\n"
        md_text += "## Priority Actions\n"
        if result.recommendations:
            for i, rec in enumerate(result.recommendations, 1):
                md_text += f"{i}. {rec}\n"
        else:
            md_text += "No immediate priority actions identified.\n\n"
            
    md_text += "\n---\n\n"
    
    # 3. Technical Notes (Bullet style for better PDF rendering)
    md_text += "## Technical Notes\n"
    md_text += f"- **Target:** {result.target}\n"
    md_text += f"- **Scan Timestamp:** {result.scan_timestamp.isoformat()}Z\n"
    md_text += f"- **Certificate Issuer:** {result.certificate_issuer if result.certificate_issuer else 'N/A'}\n"
    md_text += f"- **Certificate Expiry (Days):** {result.certificate_expires_in_days if result.certificate_expires_in_days is not None else 'N/A'}\n"
    
    dns_val = "N/A"
    if result.dns_summary and result.dns_summary.a_records:
        dns_val = ", ".join(result.dns_summary.a_records[:3])
        if len(result.dns_summary.a_records) > 3:
            dns_val += "..."
    md_text += f"- **Resolved Target IPs (A/AAAA):** {dns_val}\n\n"
    
    md_text += "---\n\n"
    
    # 4. Mandatory Passive Disclaimer
    md_text += "## Passive Assessment Disclaimer\n"
    md_text += "This report is based on passive, non-intrusive checks of publicly observable website indicators. It does not confirm exploitability, internal security posture, or the presence of specific vulnerabilities beyond the observed evidence. It should be treated as a security hardening review and does not replace an authorized penetration test or deeper application security assessment.\n"
    
    return md_text


def save_scan_result(result: ScanResult, output_dir: str = "outputs") -> tuple[str, str]:
    """
    Saves the structured JSON output and a basic PDF summary locally.
    Outputs go to '{output_dir}/scans/' and '{output_dir}/reports/'.
    """
    # Safe naming for paths
    # Get main domain name (e.g., 'cyberburgs' from 'cyberburgs.com') and capitalize it
    main_name = result.target.split('.')[0].capitalize()
    target_safe = re.sub(r'[^a-zA-Z0-9_\-]', '_', main_name)
    
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
        
    # Construct layout locally without AI injection
    md_text = build_premium_report(result)
        
    pdf_path = reports_dir / f"{target_safe}.pdf"
    render_pdf(md_text, str(pdf_path))
            
    return str(json_path), str(pdf_path)
