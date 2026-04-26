#!/usr/bin/env python3
import argparse
import base64
import io
import json
import os
import subprocess
import tarfile
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def load_key_values(path: Path):
    values = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def make_tar_bytes(paths):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path, arcname in paths:
            if path.exists():
                tar.add(path, arcname=arcname)
    return buffer.getvalue()


class EdgeHandler(BaseHTTPRequestHandler):
    server_version = "PQABSE-Edge/1.0"

    @property
    def role_dir(self) -> Path:
        return Path(self.server.role_dir)

    @property
    def script_path(self) -> Path:
        return self.role_dir / "edge_node.sh"

    @property
    def app_dir(self) -> Path:
        return self.role_dir / "app"

    @property
    def cs_url(self) -> str:
        return os.environ.get("PQ_ABSE_CS_URL", "http://127.0.0.1:8083").rstrip("/")

    @property
    def runtime_dir(self) -> Path:
        return self.app_dir / "runtime"

    def _send_json(self, status, payload):
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

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

    def _load_blockchain_state(self):
        values = load_key_values(self.runtime_dir / "state" / "blockchain_state.txt")
        return {
            "epoch": int(values.get("epoch", "0")),
            "registration_root": values.get("registration_root", ""),
            "revocation_root": values.get("revocation_root", ""),
        }

    def _load_bundle_package(self, label: str):
        bundle_bin = self.runtime_dir / "ciphertexts" / f"{label}_bundle.bin"
        bundle_meta = self.runtime_dir / "ciphertexts" / f"{label}_bundle.meta"
        if not bundle_bin.exists() or not bundle_meta.exists():
            return None
        return {
            "bundle_label": label,
            "bundle_meta": load_key_values(bundle_meta),
            "bundle_bin_base64": base64.b64encode(bundle_bin.read_bytes()).decode("ascii"),
            "bundle_meta_base64": base64.b64encode(bundle_meta.read_bytes()).decode("ascii"),
        }

    def do_GET(self):
        if self.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if self.path == "/mobile/state":
            self._send_json(HTTPStatus.OK, {"status": "ok", "blockchain_state": self._load_blockchain_state()})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self):
        if self.path == "/mobile/encrypt":
            try:
                payload = self._read_json()
            except json.JSONDecodeError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid json: {exc}"})
                return

            owner_gid = (payload.get("owner_gid") or payload.get("data_owner_gid") or "").strip()
            label = (payload.get("label") or payload.get("bundle_label") or "").strip()
            plaintext = payload.get("plaintext") or ""
            keywords = payload.get("keywords") or []
            policy_expression = (payload.get("policy_expression") or "").strip()
            policy_type = (payload.get("policy_type") or "and").strip()
            threshold = payload.get("threshold", 1)
            policy_attrs = payload.get("policy_attrs") or payload.get("policy_attributes") or []

            if not owner_gid:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: owner_gid"})
                return
            if not label:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: label"})
                return
            if not isinstance(plaintext, str) or not plaintext:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: plaintext"})
                return
            if not isinstance(keywords, list) or not all(isinstance(item, str) and item.strip() for item in keywords):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "keywords must be a non-empty string list"})
                return
            if policy_expression:
                if not isinstance(policy_expression, str):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "policy_expression must be a string"})
                    return
            elif not isinstance(policy_attrs, list) or not all(isinstance(item, str) and item.strip() for item in policy_attrs):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "policy_attrs must be a non-empty string list"})
                return

            sync_result = self._run_script("sync-state")
            if sync_result.returncode != 0:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "state sync failed", "stderr": sync_result.stderr})
                return

            args = [
                "encrypt-raw",
                owner_gid,
                label,
                plaintext,
                policy_type,
                str(threshold),
                ",".join(item.strip() for item in keywords),
                ",".join(item.strip() for item in policy_attrs),
                policy_expression,
            ]
            encrypt_result = self._run_script(*args)
            if encrypt_result.returncode != 0:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "status": "fail",
                        "error": "encrypt failed",
                        "stdout": encrypt_result.stdout,
                        "stderr": encrypt_result.stderr,
                    },
                )
                return

            bundle_package = self._load_bundle_package(label)
            if bundle_package is None:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "status": "fail",
                        "error": f"encryption succeeded but bundle files for {label} were not found",
                        "stdout": encrypt_result.stdout,
                        "stderr": encrypt_result.stderr,
                    },
                )
                return

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "stdout": encrypt_result.stdout,
                    "stderr": encrypt_result.stderr,
                    "blockchain_state": self._load_blockchain_state(),
                    "bundle": bundle_package,
                },
            )
            return

        if self.path != "/encrypt":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            payload = self._read_json()
        except json.JSONDecodeError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid json: {exc}"})
            return

        bundle = payload.get("bundle")
        request_id = payload.get("request_id") or payload.get("id") or "edge-request"
        if not bundle:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: bundle"})
            return

        sync_result = self._run_script("sync-state")
        if sync_result.returncode != 0:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "state sync failed", "stderr": sync_result.stderr})
            return

        encrypt_result = self._run_script("encrypt", bundle)
        if encrypt_result.returncode != 0:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "encrypt failed", "stderr": encrypt_result.stderr})
            return

        bundle_bin = self.app_dir / "runtime" / "ciphertexts" / f"{bundle}_bundle.bin"
        bundle_meta = self.app_dir / "runtime" / "ciphertexts" / f"{bundle}_bundle.meta"
        body = make_tar_bytes([(bundle_bin, bundle_bin.name), (bundle_meta, bundle_meta.name)])

        request = urllib.request.Request(
            f"{self.cs_url}/upload/{request_id}",
            data=body,
            headers={"Content-Type": "application/gzip"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                upload_response = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            self._send_json(HTTPStatus.BAD_GATEWAY, {"error": "upload failed", "status": exc.code, "detail": detail})
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "status": "ok",
                "request_id": request_id,
                "bundle": bundle,
                "upload_response": upload_response,
            },
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8082)
    parser.add_argument("--role-dir", required=True)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), EdgeHandler)
    server.role_dir = args.role_dir
    print(f"Edge HTTP service listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
