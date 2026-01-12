import argparse
import csv
import os
import re
import sys
import requests
from typing import Dict, Optional, Tuple


VT_BASE_URL = "https://www.virustotal.com/api/v3"

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enrich IOCs (IP/domain/hash) with VirusTotal reliability and analysis"
    )
    parser.add_argument(
        "input",
        help="Path to input file containing IOCs (one per line).",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to output CSV file.",
    )
    parser.add_argument(
        "--api-key",
        help="VirusTotal API key. If not provided, will read from VT_API_KEY env var.",
    )
    return parser.parse_args()

def get_api_key(args: argparse.Namespace) -> str:
    api_key = args.api_key or os.getenv("VT_API_KEY")
    if not api_key:
        print("[!] VirusTotal API key not provided. Use --api-key or set VT_API_KEY.", file=sys.stderr)
        sys.exit(1)
    return api_key

def load_iocs(path: str) -> list:
    iocs = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            val = line.strip()
            if not val or val.startswith("#"):
                continue
            iocs.append(val)
    return iocs

def is_ipv4(value: str) -> bool:
    ipv4_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if not re.match(ipv4_pattern, value):
        return False
    parts = value.split(".")
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

def is_hash(value: str) -> bool:
    # heuristic: hex string of length 32/40/64 (MD5/SHA1/SHA256)
    if not re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value):
        return False
    return True

def detect_indicator_type(indicator: str) -> Optional[str]:
    """
    Returns: "ip", "domain", "file_hash", or None if unknown.
    """
    if is_ipv4(indicator):
        return "ip"
    if is_hash(indicator):
        return "file_hash"
    # crude domain heuristic: contains a dot, no spaces, no scheme
    if "." in indicator and " " not in indicator and "://" not in indicator:
        return "domain"
    return None

def vt_get(api_key: str, path: str) -> Optional[dict]:
    url = f"{VT_BASE_URL}{path}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except requests.RequestException as e:
        print(f"[!] Request error for {url}: {e}", file=sys.stderr)
        return None

    if resp.status_code == 404:
        # Not found in VT
        return None

    if resp.status_code == 429:
        print("[!] Rate limit hit (HTTP 429). Consider slowing down requests.", file=sys.stderr)
        return None

    if not resp.ok:
        print(f"[!] VT API error: {resp.status_code} - {resp.text[:200]}", file=sys.stderr)
        return None

    try:
        return resp.json()
    except ValueError:
        print("[!] Failed to parse JSON response.", file=sys.stderr)
        return None
    
def query_virustotal(api_key: str, indicator: str, ioc_type: str) -> Optional[dict]:
    if ioc_type == "ip":
        path = f"/ip_addresses/{indicator}"
    elif ioc_type == "domain":
        path = f"/domains/{indicator}"
    elif ioc_type == "file_hash":
        path = f"/files/{indicator}"
    else:
        return None

    return vt_get(api_key, path)

def extract_stats(vt_response: dict) -> Tuple[Dict[str, int], str]:
    """
    Extract last_analysis_stats and derive a simple risk level.
    Returns: (stats_dict, risk_level)
    """
    stats = vt_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))

    # Simple risk scoring logic
    if malicious >= 5 or (malicious >= 1 and suspicious >= 3):
        risk = "high"
    elif malicious >= 1:
        risk = "medium"
    elif suspicious >= 1:
        risk = "low"
    elif harmless > 0 and malicious == 0 and suspicious == 0:
        risk = "probably_clean"
    else:
        risk = "unknown"

    return (
        {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
        },
        risk,
    )


def main():
    args = parse_args()
    api_key = get_api_key(args)

    iocs = load_iocs(args.input)
    if not iocs:
        print("[!] No IOCs loaded from input file.", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Loaded {len(iocs)} IOCs from {args.input}")

    with open(args.output, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "indicator",
            "type",
            "malicious",
            "suspicious",
            "harmless",
            "undetected",
            "risk_level",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ioc in iocs:
            ioc_type = detect_indicator_type(ioc)
            if not ioc_type:
                print(f"[!] Skipping unsupported indicator: {ioc}", file=sys.stderr)
                continue
            print(f"[+] Querying VT for {ioc} ({ioc_type})...")
            vt_resp = query_virustotal(api_key, ioc, ioc_type)
            if not vt_resp:
                writer.writerow(
                    {
                        "indicator": ioc,
                        "type": ioc_type,
                        "malicious": "",
                        "suspicious": "",
                        "harmless": "",
                        "undetected": "",
                        "risk_level": "no_data",
                    }
                )
                continue

            stats, risk = extract_stats(vt_resp)

            writer.writerow(
                {
                    "indicator": ioc,
                    "type": ioc_type,
                    "malicious": stats["malicious"],
                    "suspicious": stats["suspicious"],
                    "harmless": stats["harmless"],
                    "undetected": stats["undetected"],
                    "risk_level": risk,
                }
            )
    print(f"[+] Enrichment complete. Results written to {args.output}")


if __name__ == "__main__":
    main()
