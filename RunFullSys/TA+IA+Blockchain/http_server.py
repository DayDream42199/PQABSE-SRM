#!/usr/bin/env python3
import argparse
import io
import json
import os
import subprocess
import tarfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


def make_tar_bytes(base: Path, members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for relative in members:
            path = base / relative
            if path.exists():
                tar.add(path, arcname=relative)
    return buffer.getvalue()


class TaHandler(BaseHTTPRequestHandler):
    server_version = "PQABSE-TA/1.0"

    @property
    def role_dir(self) -> Path:
        return Path(self.server.role_dir)

    @property
    def app_dir(self) -> Path:
        return self.role_dir / "app"

    @property
    def script_path(self) -> Path:
        return self.role_dir / "ta_ia_blockchain.sh"

    def _send_json(self, status, payload):
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_bytes(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def _run_script(self, *args):
        return subprocess.run(
            [str(self.script_path), *args],
            cwd=self.role_dir,
            text=True,
            capture_output=True,
            check=False,
            env=os.environ.copy(),
        )

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if parsed.path == "/state/latest.tar.gz":
            body = make_tar_bytes(self.app_dir / "runtime", ["abse", "state", "cloud"])
            self._send_bytes(HTTPStatus.OK, body, "application/gzip")
            return
        if parsed.path == "/users/all.tar.gz":
            body = make_tar_bytes(self.app_dir / "runtime", ["users", "state/update_tokens"])
            self._send_bytes(HTTPStatus.OK, body, "application/gzip")
            return
        if parsed.path.startswith("/users/") and parsed.path.endswith(".tar.gz"):
            gid = parsed.path[len("/users/"):-len(".tar.gz")]
            members = [f"users/{gid}.cred", f"users/{gid}_userkey.bin", "state/update_tokens"]
            body = make_tar_bytes(self.app_dir / "runtime", members)
            self._send_bytes(HTTPStatus.OK, body, "application/gzip")
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            payload = self._read_json()
        except json.JSONDecodeError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid json: {exc}"})
            return

        routes = {
            "/setup": ("setup", None),
            "/register": ("register", "user"),
            "/refresh": ("refresh", "user"),
            "/revoke": ("revoke", "revocation"),
        }
        route = routes.get(parsed.path)
        if route is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        command, key = route
        args = [command]
        if key is not None:
            value = payload.get(key)
            if not value:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"missing field: {key}"})
                return
            args.append(value)

        result = self._run_script(*args)
        status = HTTPStatus.OK if result.returncode == 0 else HTTPStatus.INTERNAL_SERVER_ERROR
        self._send_json(
            status,
            {
                "command": args,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--role-dir", required=True)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), TaHandler)
    server.role_dir = args.role_dir
    print(f"TA HTTP service listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
