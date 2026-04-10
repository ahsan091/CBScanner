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
        console.print(Panel(f"Starting passive scan on: [bold cyan]{args.target}[/bold cyan]"))
        
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
        
    # 4. Save and Output
    json_path, pdf_path = save_scan_result(result, output_dir=args.output_dir)
    
    console.print(f"[green]✔[/green] Scan completed. Score: [bold]{result.score}/100[/bold] ({result.severity})")
    
    if score_res.recommendations:
        console.print("[bold]Top Recommendations:[/bold]")
        for i, rec in enumerate(score_res.recommendations[:3], 1):
            console.print(f"  {i}. {rec}")
            
    console.print(f"\n[dim]Results saved to:\n- {json_path}\n- {pdf_path}[/dim]")
    
    # 5. Optional Gemini Reporting
    if not args.no_ai:
        console.print("\n[yellow]Generating AI report via Gemini...[/yellow]")
        ai_pdf_path = generate_report(result, output_dir=args.output_dir)
        if ai_pdf_path:
            console.print(f"[green]✔[/green] AI Report generated and saved to: [bold]{ai_pdf_path}[/bold]")
        else:
            console.print("[dim]AI Report skipped or failed (check API limits, networking, or if GEMINI_API_KEY is properly set in .env).[/dim]")

if __name__ == "__main__":
    main()
