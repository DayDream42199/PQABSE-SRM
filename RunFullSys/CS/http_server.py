#!/usr/bin/env python3
import argparse
import base64
import io
import json
import os
import subprocess
import tarfile
import tempfile
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


def write_key_values(path: Path, values):
    lines = [f"{key}={value}" for key, value in values.items()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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

    @property
    def app_dir(self) -> Path:
        return self.role_dir / "app"

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

    def _load_blockchain_state(self):
        values = load_key_values(self.runtime_dir / "state" / "blockchain_state.txt")
        return {
            "epoch": int(values.get("epoch", "0")),
            "registration_root": values.get("registration_root", ""),
            "revocation_root": values.get("revocation_root", ""),
        }

    def _list_stored_bundle_labels(self):
        ciphertext_dir = self.runtime_dir / "ciphertexts"
        if not ciphertext_dir.exists():
            return []
        labels = []
        for meta_path in sorted(ciphertext_dir.glob("*_bundle.meta")):
            labels.append(meta_path.name[:-len("_bundle.meta")])
        return labels

    def _load_mobile_response(self, response_dir: Path):
        bundle_dir = response_dir / "bundles"
        bundles = []
        if bundle_dir.exists():
            for bundle_bin in sorted(bundle_dir.glob("*_bundle.bin")):
                label = bundle_bin.name[:-len("_bundle.bin")]
                bundle_meta = bundle_dir / f"{label}_bundle.meta"
                bundles.append(
                    {
                        "bundle_label": label,
                        "bundle_meta": load_key_values(bundle_meta),
                        "bundle_bin_base64": base64.b64encode(bundle_bin.read_bytes()).decode("ascii"),
                        "bundle_meta_base64": base64.b64encode(bundle_meta.read_bytes()).decode("ascii")
                        if bundle_meta.exists()
                        else "",
                    }
                )

        return {
            "epoch": int((response_dir / "epoch.txt").read_text(encoding="utf-8").strip() or "0")
            if (response_dir / "epoch.txt").exists()
            else 0,
            "candidate_count": int((response_dir / "candidate_count.txt").read_text(encoding="utf-8").strip() or "0")
            if (response_dir / "candidate_count.txt").exists()
            else 0,
            "exact_match_count": int((response_dir / "exact_match_count.txt").read_text(encoding="utf-8").strip() or "0")
            if (response_dir / "exact_match_count.txt").exists()
            else 0,
            "bundles": bundles,
        }

    def _rewrite_request_auth_paths(self, request_dir: Path):
        auth_token_path = request_dir / "auth_token.txt"
        auth_token_values = load_key_values(auth_token_path)
        if not auth_token_values:
            return

        updated = False
        file_map = {
            "prover_state_path": request_dir / "prover_state.json",
            "proof_file_path": request_dir / "proof.json",
            "public_file_path": request_dir / "public.json",
        }
        for key, file_path in file_map.items():
            if file_path.exists() and file_path.is_file():
                auth_token_values[key] = str(file_path)
                updated = True

        if updated:
            write_key_values(auth_token_path, auth_token_values)

    def do_GET(self):
        if self.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if self.path == "/mobile/state":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "blockchain_state": self._load_blockchain_state(),
                    "stored_bundle_labels": self._list_stored_bundle_labels(),
                },
            )
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self):
        if self.path == "/mobile/query-archive":
            try:
                payload = json.loads((self._read_body() or b"{}").decode("utf-8"))
            except json.JSONDecodeError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid json: {exc}"})
                return

            request_archive_base64 = (payload.get("request_archive_base64") or "").strip()
            if not request_archive_base64:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: request_archive_base64"})
                return

            try:
                archive_bytes = base64.b64decode(request_archive_base64, validate=True)
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid base64 payload: {exc}"})
                return

            with tempfile.TemporaryDirectory(prefix="pqabse-mobile-query-archive-") as temp_dir_name:
                temp_dir = Path(temp_dir_name)
                request_dir = temp_dir / "request"
                response_dir = temp_dir / "response"
                request_dir.mkdir()
                response_dir.mkdir()
                extract_tar_bytes(archive_bytes, request_dir)
                self._rewrite_request_auth_paths(request_dir)

                result = self._run_script("process-query-dir", str(request_dir), str(response_dir))
                if result.returncode != 0:
                    self._send_json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {
                            "status": "fail",
                            "error": "query processing failed",
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                        },
                    )
                    return

                self._send_json(
                    HTTPStatus.OK,
                    {
                        "status": "ok",
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "blockchain_state": self._load_blockchain_state(),
                        "result": self._load_mobile_response(response_dir),
                    },
                )
            return

        if self.path == "/mobile/import-bundle":
            try:
                payload = json.loads((self._read_body() or b"{}").decode("utf-8"))
            except json.JSONDecodeError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid json: {exc}"})
                return

            bundle = payload.get("bundle") or {}
            label = (bundle.get("bundle_label") or payload.get("bundle_label") or "").strip()
            bundle_bin_base64 = (bundle.get("bundle_bin_base64") or payload.get("bundle_bin_base64") or "").strip()
            bundle_meta_base64 = (bundle.get("bundle_meta_base64") or payload.get("bundle_meta_base64") or "").strip()

            if not label:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: bundle_label"})
                return
            if not bundle_bin_base64:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: bundle_bin_base64"})
                return
            if not bundle_meta_base64:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: bundle_meta_base64"})
                return

            try:
                bundle_bin_bytes = base64.b64decode(bundle_bin_base64, validate=True)
                bundle_meta_bytes = base64.b64decode(bundle_meta_base64, validate=True)
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid base64 payload: {exc}"})
                return

            with tempfile.TemporaryDirectory(prefix="pqabse-mobile-import-") as temp_dir_name:
                temp_dir = Path(temp_dir_name)
                (temp_dir / f"{label}_bundle.bin").write_bytes(bundle_bin_bytes)
                (temp_dir / f"{label}_bundle.meta").write_bytes(bundle_meta_bytes)
                result = self._run_script("import-upload-dir", str(temp_dir))

            status = HTTPStatus.OK if result.returncode == 0 else HTTPStatus.INTERNAL_SERVER_ERROR
            self._send_json(
                status,
                {
                    "status": "ok" if result.returncode == 0 else "fail",
                    "bundle_label": label,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "stored_bundle_labels": self._list_stored_bundle_labels(),
                },
            )
            return

        if self.path == "/mobile/query":
            try:
                payload = json.loads((self._read_body() or b"{}").decode("utf-8"))
            except json.JSONDecodeError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid json: {exc}"})
                return

            gid = (payload.get("gid") or "").strip()
            preferred_label = (payload.get("preferred_label") or payload.get("label") or "").strip()
            auth_token_base64 = (payload.get("auth_token_base64") or "").strip()
            shortlist_trapdoor_base64 = (payload.get("shortlist_trapdoor_base64") or "").strip()
            prover_state_base64 = (payload.get("prover_state_base64") or "").strip()
            proof_file_base64 = (payload.get("proof_file_base64") or "").strip()
            public_file_base64 = (payload.get("public_file_base64") or "").strip()

            if not gid:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: gid"})
                return
            if not auth_token_base64:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: auth_token_base64"})
                return
            if not shortlist_trapdoor_base64:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: shortlist_trapdoor_base64"})
                return

            try:
                auth_token_bytes = base64.b64decode(auth_token_base64, validate=True)
                shortlist_trapdoor_bytes = base64.b64decode(shortlist_trapdoor_base64, validate=True)
                prover_state_bytes = base64.b64decode(prover_state_base64, validate=True) if prover_state_base64 else b""
                proof_file_bytes = base64.b64decode(proof_file_base64, validate=True) if proof_file_base64 else b""
                public_file_bytes = base64.b64decode(public_file_base64, validate=True) if public_file_base64 else b""
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid base64 payload: {exc}"})
                return

            with tempfile.TemporaryDirectory(prefix="pqabse-mobile-query-") as temp_dir_name:
                temp_dir = Path(temp_dir_name)
                request_dir = temp_dir / "request"
                response_dir = temp_dir / "response"
                request_dir.mkdir()
                response_dir.mkdir()

                (request_dir / "auth_token.txt").write_bytes(auth_token_bytes)
                (request_dir / "shortlist_trapdoor.bin").write_bytes(shortlist_trapdoor_bytes)
                (request_dir / "gid.txt").write_text(gid, encoding="utf-8")
                if preferred_label:
                    (request_dir / "preferred_label.txt").write_text(preferred_label, encoding="utf-8")
                if prover_state_bytes:
                    (request_dir / "prover_state.json").write_bytes(prover_state_bytes)
                if proof_file_bytes:
                    (request_dir / "proof.json").write_bytes(proof_file_bytes)
                if public_file_bytes:
                    (request_dir / "public.json").write_bytes(public_file_bytes)

                auth_token_values = load_key_values(request_dir / "auth_token.txt")
                if auth_token_values:
                    if prover_state_bytes:
                        auth_token_values["prover_state_path"] = str(request_dir / "prover_state.json")
                    if proof_file_bytes:
                        auth_token_values["proof_file_path"] = str(request_dir / "proof.json")
                    if public_file_bytes:
                        auth_token_values["public_file_path"] = str(request_dir / "public.json")
                    write_key_values(request_dir / "auth_token.txt", auth_token_values)

                result = self._run_script("process-query-dir", str(request_dir), str(response_dir), "--skip-auth-verification")
                if result.returncode != 0:
                    self._send_json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {
                            "status": "fail",
                            "error": "query processing failed",
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                        },
                    )
                    return

                self._send_json(
                    HTTPStatus.OK,
                    {
                        "status": "ok",
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "blockchain_state": self._load_blockchain_state(),
                        "result": self._load_mobile_response(response_dir),
                    },
                )
            return

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
                self._rewrite_request_auth_paths(request_dir)
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
