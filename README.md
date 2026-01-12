# virus_total_IOC

# Automated IOC Enrichment with VirusTotal

## Goal
Given a list of Indicators of Compromise (IOCs) (IPs, domains, file hashes), automatically query VirusTotal, extract key reputation fields, and output a clean CSV summary for analysts.


## IOC
Indicator of Compromise (IoC) is digital evidence, like a malicious IP address, unusual file hash, or strange network traffic, that signals a network or system has been breached, helping security teams detect, investigate, and respond to attacks by finding "digital breadcrumbs" left by attackers

## Objectives
- Integrate with an external security intelligence platform (VirusTotal).
- Automate enrichment of IOCs.
- Produce analyst-ready data for triage workflows, SIEMs, or SOAR playbooks.

## Solution Overview
This project includes a Python script, `virus_total_IOC.py`, that:

- Ingests IOCs from a text file (one per line).
- Ignores comments (`#`) and empty lines.
- Classifies the indicator type:
  - IPv4 (e.g., `1.2.3.4`)
  - Domain (e.g., `example.com`)
  - File hash (MD5/SHA1/SHA256)
- Queries VirusTotal v3:
  - `/ip_addresses/{ip}` for IPs
  - `/domains/{domain}` for domains
  - `/files/{hash}` for file hashes
- Extracts reputation stats from `last_analysis_stats`:
  - `malicious`, `suspicious`, `harmless`, `undetected`
- Derives a simple risk level:
  - `high`: clearly malicious (e.g., >= 5 malicious detections or malicious + several suspicious)
  - `medium`: at least one malicious detection
  - `low`: only suspicious detections
  - `probably_clean`: harmless > 0 and no malicious/suspicious
  - `unknown` / `no_data`: no strong signal or missing data
- Outputs a CSV with one row per indicator:
  - `indicator`, `type`, detection counts, `risk_level`

## How It Works (Technical Details)
### Input Handling
- Reads the file line-by-line to avoid loading large lists into memory.
- Uses simple heuristics:
  - `is_ipv4`: regex + 0-255 checks
  - `is_hash`: hex string length of 32, 40, or 64
  - otherwise treat as domain if it has a dot and no scheme

### API Integration
- Uses Python `requests` to call VirusTotal v3 REST API.
- Authentication via `x-apikey` header from:
  - `--api-key` argument, or
  - `VT_API_KEY` environment variable
- Handles:
  - `404` (no data for this IOC)
  - `429` (rate-limit warning)
  - general HTTP and JSON parsing errors

### Risk Logic
The risk engine is intentionally simple but explainable:
- Multiple AV engines marking an indicator as malicious -> `high`
- Single malicious engine hit -> `medium`
- Only "suspicious" flags -> `low`
- Only "harmless" and "undetected" -> `probably_clean`
- No stats available -> `unknown` / `no_data`

## Example Workflow
1. Threat intel team publishes a list of suspicious IPs and hashes.
2. Drop them into `iocs.txt`.
3. Run:

```bash
export VT_API_KEY="..."
python3 virus_total_IOC.py iocs.txt --output out.csv
```

4. Load the CSV into:
- SIEM as a lookup table
- Excel/Sheets for quick filtering
- SOAR playbook as enrichment input

Focus triage on `risk_level = high` or `medium`, de-prioritizing `probably_clean` or `unknown`.
