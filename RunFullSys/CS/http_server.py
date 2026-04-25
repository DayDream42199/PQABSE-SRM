#!/usr/bin/env python3
import argparse
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def tar_directory(directory: Path) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for child in sorted(directory.iterdir()):
            tar.add(child, arcname=child.name)
    return buffer.getvalue()


def extract_tar_bytes(payload: bytes, destination: Path):
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
        tar.extractall(destination)


class CsHandler(BaseHTTPRequestHandler):
    server_version = "PQABSE-CS/1.0"

    @property
    def role_dir(self) -> Path:
        return Path(self.server.role_dir)

    @property
    def script_path(self) -> Path:
        return self.role_dir / "cs.sh"

    def _send_json(self, status, payload):
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_bytes(self, status, payload, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

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
        if self.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self):
        if self.path.startswith("/upload/"):
            request_id = self.path.split("/", 2)[2]
            payload = self._read_body()
            with tempfile.TemporaryDirectory(prefix="pqabse-upload-") as temp_dir_name:
                temp_dir = Path(temp_dir_name)
                extract_tar_bytes(payload, temp_dir)
                result = self._run_script("import-upload-dir", str(temp_dir))
            status = HTTPStatus.OK if result.returncode == 0 else HTTPStatus.INTERNAL_SERVER_ERROR
            self._send_json(
                status,
                {"status": "ok" if result.returncode == 0 else "fail", "request_id": request_id, "stderr": result.stderr},
            )
            return

        if self.path.startswith("/query/"):
            request_id = self.path.split("/", 2)[2]
            payload = self._read_body()
            with tempfile.TemporaryDirectory(prefix="pqabse-query-") as temp_dir_name:
                temp_dir = Path(temp_dir_name)
                request_dir = temp_dir / "request"
                response_dir = temp_dir / "response"
                request_dir.mkdir()
                response_dir.mkdir()
                extract_tar_bytes(payload, request_dir)
                result = self._run_script("process-query-dir", str(request_dir), str(response_dir))
                if result.returncode != 0:
                    self._send_json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {"status": "fail", "request_id": request_id, "stderr": result.stderr, "stdout": result.stdout},
                    )
                    return
                body = tar_directory(response_dir)
            self._send_bytes(HTTPStatus.OK, body, "application/gzip")
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8083)
    parser.add_argument("--role-dir", required=True)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), CsHandler)
    server.role_dir = args.role_dir
    print(f"CS HTTP service listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
