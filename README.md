# SentinelX — Defensive Security Assessment Starter

A lightweight, manually built starter project using Python's standard library only:
- Python HTTP server (`http.server`)
- SQLite persistence
- Static HTML/CSS/JavaScript dashboard
- HTTP security-header assessment
- Scan history and findings

## Requirements
- Python 3.10+ recommended
- No pip packages required

## Run
```bash
cd sentinelx
python3 app.py
```
Open http://127.0.0.1:8000

## Current scope
This is a local development starter, not a production-ready security scanner. It checks HTTP response security headers for a single public HTTPS/HTTP website, stores results locally, and shows remediation advice. It does not exploit vulnerabilities or perform intrusive tests.

## Safety notes
- Only scan systems you own or have explicit permission to assess.
- The scanner rejects localhost, private, loopback, link-local, multicast, reserved, and non-global IP destinations.
- Redirects are disabled so a public URL cannot redirect the scanner into an internal network.
- DNS validation is best-effort in this starter; production deployment needs DNS-rebinding-resistant connection pinning, strict egress firewall rules, per-user rate limits, authentication, and isolation.
- Do not expose this development server to the public internet.
