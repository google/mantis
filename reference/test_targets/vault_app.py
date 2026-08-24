#!/usr/bin/env python3
"""Document Vault & Analysis Service (Vulnerable Test Target for Mantis).

This micro-service provides document retrieval, word count preview, and status
reporting. It contains intentional security vulnerabilities designed to exercise
Mantis's static detection, dynamic exploit reproduction, and patch generation:
1. Path Traversal in /view: Unsanitized file parameter allows arbitrary file read.
2. Command Injection in /preview: Unescaped shell command parameter execution.
"""

import argparse
import http.server
import json
import os
import subprocess
import sys
import urllib.parse

PORT = 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOCS_DIR = os.path.join(BASE_DIR, "documents")


class VaultHTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for document storage and inspection."""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # Health & Status Endpoint
        if parsed.path == "/" or parsed.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "service": "vault_app"}).encode("utf-8"))
            return

        # 1. Path Traversal Vulnerability in /view
        if parsed.path == "/view":
            filename = params.get("file", [""])[0]
            if not filename:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Error: 'file' query parameter required")
                return

            # Flaw: os.path.join with unsanitized filename allows path traversal (e.g. ../../../../etc/passwd)
            target_path = os.path.join(DOCS_DIR, filename)
            try:
                with open(target_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(f"File not found: {filename}".encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Internal error: {e}".encode("utf-8"))
            return

        # 2. Command Injection Vulnerability in /preview
        if parsed.path == "/preview":
            filename = params.get("file", [""])[0]
            if not filename:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Error: 'file' query parameter required")
                return

            # Flaw: shell=True with unquoted input allows arbitrary command execution (e.g. file=test.txt;id)
            cmd = f"wc -w {DOCS_DIR}/{filename}"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({
                    "file": filename,
                    "word_count_output": res.stdout.strip(),
                    "exit_code": res.returncode,
                }).encode("utf-8")
            )
            return

        # Not Found
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Endpoint not found")

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP access logging during tests
        sys.stderr.write(f"[VaultApp] {self.address_string()} - {format % args}\n")


def init_workspace():
    """Initializes sample document storage."""
    os.makedirs(DOCS_DIR, exist_ok=True)
    sample_file = os.path.join(DOCS_DIR, "welcome.txt")
    if not os.path.exists(sample_file):
        with open(sample_file, "w") as f:
            f.write("Welcome to the Mantis Vault Secure Storage.\n")


def main():
    parser = argparse.ArgumentParser(description="Document Vault Test Application")
    parser.add_argument("--port", type=int, default=PORT, help="Port to listen on")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    args = parser.parse_args()

    init_workspace()
    server_address = (args.host, args.port)
    httpd = http.server.HTTPServer(server_address, VaultHTTPHandler)
    print(f"Vault App running at http://{args.host}:{args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Vault App.")
        httpd.server_close()


if __name__ == "__main__":
    main()
