#!/usr/bin/env python3
"""SentinelX local defensive security dashboard — standard-library starter."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from urllib.request import (
    Request,
    build_opener,
    HTTPHandler,
    HTTPSHandler,
    HTTPRedirectHandler,
)
from urllib.error import URLError, HTTPError
import ipaddress
import json
import socket
import sqlite3
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "sentinelx.db"
HOST = "127.0.0.1"
PORT = 8000
MAX_BODY = 16_384
TIMEOUT = 8
USER_AGENT = "SentinelX-Defensive-Header-Checker/0.1"

HEADER_RULES = [
    ("strict-transport-security", "high", "Enforce HTTPS with an appropriate Strict-Transport-Security policy. Only enable HSTS after confirming the site works fully over HTTPS."),
    ("content-security-policy", "high", "Define a Content-Security-Policy appropriate to the application to reduce the impact of injected content."),
    ("x-content-type-options", "medium", "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing."),
    ("x-frame-options", "medium", "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."),
    ("referrer-policy", "low", "Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin."),
    ("permissions-policy", "low", "Set a Permissions-Policy that disables browser capabilities the application does not need."),
]

def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, target TEXT NOT NULL, checked_at TEXT NOT NULL,
            http_status INTEGER, server TEXT, findings_json TEXT NOT NULL,
            headers_json TEXT NOT NULL, error TEXT
        )""")
        db.commit()

def validate_target(raw):
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Enter a website URL.")
    raw = raw.strip()
    if len(raw) > 2048:
        raise ValueError("URL is too long.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise ValueError("Enter a valid hostname.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")
    if parsed.port not in (None, 80, 443):
        raise ValueError("Custom ports are not allowed in this starter.")
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise ValueError("Local hostnames are not allowed.")
    try:
        literal_ip = ipaddress.ip_address(host)
        if not literal_ip.is_global:
            raise ValueError("Private, local, reserved, and non-public IPs are blocked.")
    except ValueError as exc:
        if str(exc) == "Private, local, reserved, and non-public IPs are blocked.":
            raise
        # A non-IP hostname proceeds to DNS validation.
        if any(not label or len(label) > 63 for label in host.split(".")):
            raise ValueError("Invalid hostname.")
        if len(host) > 253 or "." not in host:
            raise ValueError("Enter a fully qualified public hostname.")
    try:
        answers = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                     type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("Hostname could not be resolved.")
    if not answers:
        raise ValueError("Hostname did not resolve to an address.")
    for answer in answers:
        ip = ipaddress.ip_address(answer[4][0])
        if not ip.is_global:
            raise ValueError("Hostname resolves to a non-public address; request blocked.")
    # Normalize away fragments, preserve path/query, and avoid implicit credentials.
    netloc = host
    return parsed._replace(netloc=netloc).geturl()

class _NoRedirectHandler(HTTPRedirectHandler):
    """Prevent urllib from following redirects during security scans."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def analyze_headers(headers):
    lower = {k.lower(): v for k, v in headers.items()}
    findings = []
    for name, severity, advice in HEADER_RULES:
        if name not in lower:
            findings.append({
                "title": f"Missing {name}",
                "severity": severity,
                "category": "HTTP security headers",
                "evidence": f"The response did not include the {name} header.",
                "remediation": advice,
            })
    if "server" in lower:
        findings.append({
            "title": "Server header is disclosed",
            "severity": "info",
            "category": "Information disclosure",
            "evidence": f"Server: {str(lower['server'])[:160]}",
            "remediation": "Consider minimizing version and implementation details in response headers. This header alone does not prove a vulnerability.",
        })
    if "x-powered-by" in lower:
        findings.append({
            "title": "X-Powered-By header is disclosed",
            "severity": "low",
            "category": "Information disclosure",
            "evidence": f"X-Powered-By: {str(lower['x-powered-by'])[:160]}",
            "remediation": "Remove unnecessary technology-identifying headers where feasible.",
        })
    return findings

def perform_scan(raw_target):
    target = validate_target(raw_target)
    request = Request(target, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"})
    context = ssl.create_default_context()
    opener = build_opener(_NoRedirectHandler(), HTTPSHandler(context=context), HTTPHandler())
    started = time.monotonic()
    status = None
    server = ""
    headers_out = {}
    error = None
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            status = response.status
            headers_out = {k: v for k, v in response.headers.items()}
            server = response.headers.get("Server", "")
            # Do not download a page body; header analysis is sufficient.
    except HTTPError as exc:
        # A 3xx response is intentionally not followed. Other HTTP errors still carry useful headers.
        status = exc.code
        headers_out = {k: v for k, v in exc.headers.items()} if exc.headers else {}
        server = headers_out.get("Server", "")
        if 300 <= exc.code < 400:
            error = "Redirect refused by design; resubmit the final destination URL directly."
    except (URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        error = f"Connection failed: {str(reason)[:240]}"
    findings = analyze_headers(headers_out) if headers_out else []
    if error and not findings:
        findings.append({
            "title": "Assessment could not be completed",
            "severity": "info",
            "category": "Scan status",
            "evidence": error,
            "remediation": "Verify the URL, DNS, certificate, and network reachability. No security conclusion can be drawn from a failed connection.",
        })
    result = {
        "id": str(uuid.uuid4()),
        "target": target,
        "checked_at": utcnow(),
        "http_status": status,
        "server": server,
        "findings": findings,
        "headers": headers_out,
        "error": error,
        "duration_ms": round((time.monotonic() - started) * 1000),
    }
    with sqlite3.connect(DB_PATH) as db:
        db.execute("INSERT INTO scans (id,target,checked_at,http_status,server,findings_json,headers_json,error) VALUES (?,?,?,?,?,?,?,?)",
                   (result["id"], target, result["checked_at"], status, server,
                    json.dumps(findings), json.dumps(headers_out), error))
        db.commit()
    return result

def list_scans(limit=50):
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT * FROM scans ORDER BY checked_at DESC LIMIT ?", (limit,)).fetchall()
    result = []
    for row in rows:
        findings = json.loads(row["findings_json"])
        result.append({
            "id": row["id"], "target": row["target"], "checked_at": row["checked_at"],
            "http_status": row["http_status"], "server": row["server"],
            "findings": findings, "headers": json.loads(row["headers_json"]), "error": row["error"],
        })
    return result

def json_response(handler, data, status=200):
    payload = json.dumps(data).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:")
    handler.end_headers()
    handler.wfile.write(payload)

class Handler(BaseHTTPRequestHandler):
    server_version = "SentinelXDev/0.1"
    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            return json_response(self, {"ok": True, "service": "SentinelX", "time": utcnow()})
        if parsed.path == "/api/scans":
            return json_response(self, {"scans": list_scans()})
        if parsed.path == "/api/summary":
            scans = list_scans()
            findings = [f for scan in scans for f in scan["findings"]]
            return json_response(self, {
                "assets_assessed": len({s["target"] for s in scans}),
                "scans_completed": len(scans),
                "open_findings": len([f for f in findings if f["severity"] != "info"]),
                "critical_findings": len([f for f in findings if f["severity"] == "critical"]),
                "recent_scans": scans[:5],
            })
        if parsed.path == "/":
            return self.serve_static("index.html")
        if parsed.path == "/styles.css":
            return self.serve_static("styles.css", "text/css; charset=utf-8")
        if parsed.path == "/app.js":
            return self.serve_static("app.js", "text/javascript; charset=utf-8")
        self.send_error(404, "Not found")

    def do_POST(self):
        if urlparse(self.path).path != "/api/scans":
            return json_response(self, {"error": "Not found"}, 404)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                return json_response(self, {"error": "Request body is empty or too large."}, 400)
            body = json.loads(self.rfile.read(length))
            target = body.get("target", "")
            result = perform_scan(target)
            return json_response(self, result)
        except ValueError as exc:
            return json_response(self, {"error": str(exc)}, 400)
        except json.JSONDecodeError:
            return json_response(self, {"error": "Invalid JSON body."}, 400)
        except Exception as exc:
            print(f"[scan-error] {type(exc).__name__}: {exc}")
            return json_response(self, {"error": "Unexpected scan error. Check the local server log."}, 500)

    def serve_static(self, filename, content_type="text/html; charset=utf-8"):
        path = BASE_DIR / "static" / filename
        try:
            data = path.read_bytes()
        except OSError:
            return self.send_error(404, "Static file not found")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"SentinelX running at http://{HOST}:{PORT}")
    print("Local development only. Do not expose this server to the public internet.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down SentinelX.")
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
