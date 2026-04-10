import argparse
import sys
import json
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from dotenv import load_dotenv

# Local imports
from scanner.url_normalizer import normalize_target
from scanner.http_checker import check_http_https
from scanner.tls_checker import check_tls
from scanner.dns_checker import check_dns
from scanner.header_checker import check_headers
from scanner.cookie_checker import check_cookies
from scanner.exposure_checker import check_exposure
from scanner.scorer import calculate_score
from scanner.reporter import save_scan_result
from scanner.schemas import ScanResult
from ai.gemini_client import generate_report

def int_to_text(n: int) -> str:
    """Converts small integers to English words for UI polish."""
    words = {
        0: "Zero", 1: "One", 2: "Two", 3: "Three", 4: "Four", 5: "Five",
        6: "Six", 7: "Seven", 8: "Eight", 9: "Nine", 10: "Ten",
        11: "Eleven", 12: "Twelve", 13: "Thirteen", 14: "Fourteen", 15: "Fifteen"
    }
    return words.get(n, str(n))

def main():
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="Passive Website Security Posture Scanner")
    parser.add_argument("target", help="The domain or URL to scan (e.g., example.com)")
    parser.add_argument("--no-ai", action="store_true", help="Disable Gemini AI report generation")
    parser.add_argument("--json-only", action="store_true", help="Output only the raw JSON to stdout")
    parser.add_argument("--output-dir", default="outputs", help="Directory to save the local JSON and PDF reports")
    
    args = parser.parse_args()
    console = Console()
    
    if not args.json_only:
        console.print("═══════════════════════════════════════════════════════════════════════", style="dim", justify="center")
        console.print("CBScanner", style="bold cyan", justify="center")
        console.print("═══════════════════════════════════════════════════════════════════════\n", style="dim", justify="center")
        
    target_info = normalize_target(args.target)
    
    # 1. Run Checks
    dns_res = check_dns(target_info.domain)
    tls_res = check_tls(target_info.domain)
    http_res = check_http_https(target_info.domain)
    
    present_headers = []
    missing_headers = []
    cookie_issues = []
    metadata_exposure = []
    
    if http_res.primary_response:
        headers_res = check_headers(http_res.primary_response.headers)
        present_headers = headers_res.present_headers
        missing_headers = headers_res.missing_headers
        
        cookie_issues = check_cookies(http_res.primary_response)
        metadata_exposure = check_exposure(http_res.primary_response.headers)
        
    # 2. Score
    score_res = calculate_score(
        https_enabled=http_res.https_enabled,
        http_redirect_to_https=http_res.http_redirect_to_https,
        certificate_valid=tls_res.certificate_valid,
        certificate_expires_in_days=tls_res.certificate_expires_in_days,
        missing_headers=missing_headers,
        cookie_issues=cookie_issues,
        metadata_exposure=metadata_exposure
    )
    
    # 3. Assemble
    result = ScanResult(
        target=target_info.domain,
        scan_timestamp=datetime.now(timezone.utc),
        https_enabled=http_res.https_enabled,
        http_redirect_to_https=http_res.http_redirect_to_https,
        certificate_valid=tls_res.certificate_valid,
        certificate_expires_in_days=tls_res.certificate_expires_in_days,
        certificate_issuer=tls_res.certificate_issuer,
        dns_summary=dns_res,
        present_headers=present_headers,
        missing_headers=missing_headers,
        cookie_issues=cookie_issues,
        metadata_exposure=metadata_exposure,
        score=score_res.score,
        severity=score_res.severity,
        recommendations=score_res.recommendations
    )
    
    if args.json_only:
        print(json.dumps(result.to_json_dict(), indent=2))
        sys.exit(0)
        
    # 4. Save and Output Layout
    json_path, pdf_path = save_scan_result(result, output_dir=args.output_dir)
    
    if not args.json_only:
        console.print(f" [bold bright_blue]Target[/bold bright_blue]      [bold]{result.target}[/bold]")
        console.print(f" [bold bright_blue]Timestamp[/bold bright_blue]   {result.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        mode_str = "Passive Scanning"
        console.print(f" [bold bright_blue]Mode[/bold bright_blue]        {mode_str}\n")
        
        color = "green" if result.score >= 80 else "yellow" if result.score >= 50 else "red"
        console.print(f" [bold bright_blue]Score[/bold bright_blue]       [bold bright_magenta]{result.score}/100[/bold bright_magenta]")
        console.print(f" [bold bright_blue]Severity[/bold bright_blue]    [bold bright_magenta]{result.severity}[/bold bright_magenta]\n")
        
        console.print(" [bold]Findings[/bold]")
        https_msg = "HTTPS enabled and redirect enforced" if (result.https_enabled and result.http_redirect_to_https) else "HTTPS missing or incomplete"
        console.print(f"   • {https_msg}")
        
        cert_msg = f"TLS certificate valid ({result.certificate_expires_in_days} days remaining)" if result.certificate_valid else "TLS certificate invalid or missing"
        console.print(f"   • {cert_msg}")
        
        count = len(result.missing_headers)
        hdrs_label = "header" if count == 1 else "headers"
        hdrs_msg = f"{int_to_text(count)} important security {hdrs_label} missing" if result.missing_headers else "Security headers present"
        console.print(f"   • {hdrs_msg}")
        
        cookie_msg = f"{len(result.cookie_issues)} cookie security issues detected" if result.cookie_issues else "No cookie security issues detected"
        console.print(f"   • {cookie_msg}")
        
        if result.metadata_exposure:
             count = len(result.metadata_exposure)
             elem_label = "element" if count == 1 else "elements"
             console.print(f"   • Server metadata exposed ({int_to_text(count)} {elem_label})")
        
        console.print("\n [bold]Top Priority Actions[/bold]")
        if score_res.recommendations:
            for i, rec in enumerate(score_res.recommendations[:3], 1):
                # Clean periods out for cleaner UI matching mockup
                clean_rec = rec.split('.')[0] if '.' in rec else rec
                console.print(f"   [white]{i}.[/white] {clean_rec}")
        else:
            console.print("   • No immediate priority actions required.")
            

        
        # 5. Optional Gemini Reporting
        if not args.no_ai:
             console.print("\n [bold]AI Report[/bold]")
             with console.status(" [dim]Connecting to Gemini API...[/dim]", spinner="dots"):
                 ai_markdown = generate_report(result)
             if ai_markdown:
                 from scanner.reporter import build_premium_report, render_pdf
                 premium_layout = build_premium_report(result, ai_content=ai_markdown)
                 render_pdf(premium_layout, pdf_path)
        
        console.print(f"\n [bold green][✓][/bold green] Report Ready → [bold white]{pdf_path}[/bold white]\n")

if __name__ == "__main__":
    main()
