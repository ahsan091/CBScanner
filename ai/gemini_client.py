import os
import re
import json
import time
from pathlib import Path
from google import genai
from google.genai import types

from .prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from scanner.schemas import ScanResult

def generate_report(scan_result: ScanResult) -> str | None:
    api_key = os.getenv("GEMINI_API_KEY")
    # If the user sets the key to empty string or doesn't have it, we skip gently
    if not api_key or api_key == "your_api_key_here":
        return None
        
    client = genai.Client(api_key=api_key)
    
    # Dump strictly as string
    scan_json_str = json.dumps(scan_result.to_json_dict(), indent=2)
    user_prompt = USER_PROMPT_TEMPLATE.replace("{scan_json}", scan_json_str)
    
    models = ['gemini-2.5-flash', 'gemini-3-flash-preview', 'gemini-3.1-flash-lite-preview']
    max_retries = 3
    
    for attempt in range(max_retries):
        for model in models:
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=user_prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_PROMPT,
                        temperature=0.2
                    )
                )
                report_text = response.text
                
                if not report_text:
                    return None
                    
                return report_text
                
            except Exception as e:
                error_msg = str(e)
                if '503' in error_msg or '429' in error_msg:
                    print(f"    [dim]Attempt {attempt + 1}: Model {model} is busy. Trying next...[/dim]")
                    continue
                else:
                    print(f"\n[!] Failed to generate Gemini report: {e}")
                    return None
                    
        # If loop finishes without returning, all models failed (503 or 429)
        if attempt < max_retries - 1:
            print(f"    [yellow]All models hit maximum capacity. Waiting 5 seconds before retry {attempt + 2}/{max_retries}...[/yellow]")
            time.sleep(5)
            
    print("\n[!] AI report could not be generated due to temporary API unavailability. Core scan results are complete.")
    return None
