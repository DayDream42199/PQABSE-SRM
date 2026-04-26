#!/usr/bin/env python3
import argparse
import base64
import shutil
import io
import json
import os
import subprocess
import tarfile
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import request as urllib_request


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


def tar_directory(directory: Path, archive_path: Path):
    with tarfile.open(archive_path, mode="w:gz") as tar:
        for child in sorted(directory.iterdir()):
            tar.add(child, arcname=child.name)


def extract_archive(archive_path: Path, destination: Path):
    with tarfile.open(archive_path, mode="r:gz") as tar:
        tar.extractall(destination)


def tar_directory_bytes(directory: Path) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for child in sorted(directory.iterdir()):
            tar.add(child, arcname=child.name)
    return buffer.getvalue()


class MduHandler(BaseHTTPRequestHandler):
    server_version = "PQABSE-MDU/1.0"

    @property
    def role_dir(self) -> Path:
        return Path(self.server.role_dir)

    @property
    def app_dir(self) -> Path:
        return self.role_dir / "app"

    @property
    def build_dir(self) -> Path:
        return self.app_dir / "build-wsl"

    @property
    def script_path(self) -> Path:
        return self.role_dir / "mdu.sh"

    @property
    def runtime_dir(self) -> Path:
        return self.app_dir / "runtime"

    @property
    def cs_url(self) -> str:
        return os.environ.get("PQ_ABSE_CS_URL", "http://127.0.0.1:8083").rstrip("/")

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

    def _run_binary(self, name: str, *args):
        return subprocess.run(
            [str(self.build_dir / name), *args],
            cwd=self.app_dir,
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

    def _read_base64_file(self, path: Path):
        if not str(path) or not path.exists() or not path.is_file():
            return ""
        return base64.b64encode(path.read_bytes()).decode("ascii")

    def _augment_request_dir(self, request_dir: Path):
        verification_key = self.app_dir / "zk" / "build" / "setup" / "verification_key.json"
        if verification_key.exists() and verification_key.is_file():
            shutil.copy2(verification_key, request_dir / "verification_key.json")

    def _load_mobile_query_package(self, request_dir: Path):
        auth_token_path = request_dir / "auth_token.txt"
        shortlist_path = request_dir / "shortlist_trapdoor.bin"
        preferred_label_path = request_dir / "preferred_label.txt"
        gid_path = request_dir / "gid.txt"

        auth_token_values = load_key_values(auth_token_path)
        if not auth_token_values or not shortlist_path.exists():
            return None

        preferred_label = preferred_label_path.read_text(encoding="utf-8").strip() if preferred_label_path.exists() else ""
        gid = gid_path.read_text(encoding="utf-8").strip() if gid_path.exists() else auth_token_values.get("user_gid", "")

        return {
            "gid": gid,
            "preferred_label": preferred_label,
            "auth_token": auth_token_values,
            "auth_token_base64": self._read_base64_file(auth_token_path),
            "shortlist_trapdoor_base64": self._read_base64_file(shortlist_path),
            "prover_state_base64": self._read_base64_file(Path(auth_token_values.get("prover_state_path", ""))),
            "proof_file_base64": self._read_base64_file(Path(auth_token_values.get("proof_file_path", ""))),
            "public_file_base64": self._read_base64_file(Path(auth_token_values.get("public_file_path", ""))),
        }

    def _submit_query_archive(self, request_dir: Path, response_dir: Path, request_id: str):
        with tempfile.TemporaryDirectory(prefix="pqabse-mdu-archive-") as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            archive_path = temp_dir / "request.tar.gz"
            response_archive = temp_dir / "response.tar.gz"
            tar_directory(request_dir, archive_path)

            with archive_path.open("rb") as body_stream:
                req = urllib_request.Request(
                    url=f"{self.cs_url}/query/{request_id}",
                    data=body_stream.read(),
                    headers={"Content-Type": "application/gzip"},
                    method="POST",
                )
            with urllib_request.urlopen(req, timeout=180) as response:
                response_archive.write_bytes(response.read())

            extract_archive(response_archive, response_dir)

    def _parse_decrypt_stdout(self, stdout: str):
        results = []
        lines = stdout.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line.startswith("Bundle: "):
                i += 1
                continue

            bundle_label = line[len("Bundle: "):].strip()
            matched_keywords = []
            plaintext_lines = []
            i += 1

            if i < len(lines) and lines[i].startswith("Matched keywords:"):
                matched_keywords = [item for item in lines[i][len("Matched keywords:"):].strip().split(" ") if item]
                i += 1

            if i < len(lines) and lines[i] == "Plaintext:":
                i += 1
                while i < len(lines) and not lines[i].startswith("Bundle: ") and not lines[i].startswith("Retrieve/decrypt ms:"):
                    plaintext_lines.append(lines[i])
                    i += 1

            results.append(
                {
                    "bundle_label": bundle_label,
                    "matched_keywords": matched_keywords,
                    "plaintext": "\n".join(plaintext_lines).strip(),
                }
            )

        return results

    def do_GET(self):
        if self.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if self.path == "/mobile/state":
            sync_state = self._run_script("sync-state")
            sync_users = self._run_script("sync-users")
            status = HTTPStatus.OK if sync_state.returncode == 0 and sync_users.returncode == 0 else HTTPStatus.INTERNAL_SERVER_ERROR
            self._send_json(
                status,
                {
                    "status": "ok" if status == HTTPStatus.OK else "fail",
                    "blockchain_state": self._load_blockchain_state(),
                    "sync_state_stdout": sync_state.stdout,
                    "sync_state_stderr": sync_state.stderr,
                    "sync_users_stdout": sync_users.stdout,
                    "sync_users_stderr": sync_users.stderr,
                },
            )
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self):
        if self.path == "/mobile/prepare-query":
            try:
                payload = self._read_json()
            except json.JSONDecodeError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid json: {exc}"})
                return

            gid = (payload.get("gid") or "").strip()
            preferred_label = (payload.get("preferred_label") or payload.get("label") or "").strip()
            keywords = payload.get("keywords") or []
            if not gid:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: gid"})
                return
            if not isinstance(keywords, list) or not all(isinstance(item, str) and item.strip() for item in keywords):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "keywords must be a non-empty string list"})
                return

            sync_state = self._run_script("sync-state")
            if sync_state.returncode != 0:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"status": "fail", "error": "failed to sync state from TA", "stdout": sync_state.stdout, "stderr": sync_state.stderr},
                )
                return

            sync_users = self._run_script("sync-users")
            if sync_users.returncode != 0:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"status": "fail", "error": "failed to sync user materials from TA", "stdout": sync_users.stdout, "stderr": sync_users.stderr},
                )
                return

            with tempfile.TemporaryDirectory(prefix="pqabse-mdu-prepare-") as temp_dir_name:
                request_dir = Path(temp_dir_name) / "request"
                request_dir.mkdir()

                prepare_args = ["--gid", gid, "--out-dir", str(request_dir)]
                if preferred_label:
                    prepare_args.extend(["--label", preferred_label])
                for keyword in keywords:
                    prepare_args.extend(["--query-keyword", keyword.strip()])

                prepare = self._run_binary("mdu_prepare_query", *prepare_args)
                if prepare.returncode != 0:
                    self._send_json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {
                            "status": "fail",
                            "error": "failed to prepare query artifacts",
                            "stdout": prepare.stdout,
                            "stderr": prepare.stderr,
                        },
                    )
                    return

                self._augment_request_dir(request_dir)
                query_package = self._load_mobile_query_package(request_dir)
                if query_package is None:
                    self._send_json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {
                            "status": "fail",
                            "error": "query preparation succeeded but no mobile query package was found",
                            "stdout": prepare.stdout,
                            "stderr": prepare.stderr,
                        },
                    )
                    return

                self._send_json(
                    HTTPStatus.OK,
                    {
                        "status": "ok",
                        "stdout": prepare.stdout,
                        "stderr": prepare.stderr,
                        "query_package": query_package,
                        "request_archive_base64": base64.b64encode(tar_directory_bytes(request_dir)).decode("ascii"),
                        "phase1_params_base64": self._read_base64_file(self.runtime_dir / "abse" / "phase1_params.txt"),
                        "blockchain_state": self._load_blockchain_state(),
                    },
                )
            return

        if self.path != "/mobile/search-decrypt":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        try:
            payload = self._read_json()
        except json.JSONDecodeError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid json: {exc}"})
            return

        gid = (payload.get("gid") or "").strip()
        preferred_label = (payload.get("preferred_label") or payload.get("label") or "").strip()
        keywords = payload.get("keywords") or []
        if not gid:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: gid"})
            return
        if not isinstance(keywords, list) or not all(isinstance(item, str) and item.strip() for item in keywords):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "keywords must be a non-empty string list"})
            return

        sync_state = self._run_script("sync-state")
        if sync_state.returncode != 0:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"status": "fail", "error": "failed to sync state from TA", "stdout": sync_state.stdout, "stderr": sync_state.stderr},
            )
            return

        sync_users = self._run_script("sync-users")
        if sync_users.returncode != 0:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"status": "fail", "error": "failed to sync user materials from TA", "stdout": sync_users.stdout, "stderr": sync_users.stderr},
            )
            return

        with tempfile.TemporaryDirectory(prefix="pqabse-mdu-search-") as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            request_dir = temp_dir / "request"
            response_dir = temp_dir / "response"
            request_dir.mkdir()
            response_dir.mkdir()
            request_id = temp_dir.name

            prepare_args = ["--gid", gid, "--out-dir", str(request_dir)]
            if preferred_label:
                prepare_args.extend(["--label", preferred_label])
            for keyword in keywords:
                prepare_args.extend(["--query-keyword", keyword.strip()])

            prepare = self._run_binary("mdu_prepare_query", *prepare_args)
            if prepare.returncode != 0:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "status": "fail",
                        "error": "failed to prepare query artifacts",
                        "stdout": prepare.stdout,
                        "stderr": prepare.stderr,
                    },
                )
                return

            self._augment_request_dir(request_dir)
            try:
                self._submit_query_archive(request_dir, response_dir, request_id)
            except Exception as exc:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"status": "fail", "error": f"failed to query CS: {exc}"},
                )
                return

            decrypt = self._run_binary(
                "mdu_decrypt_response",
                "--gid",
                gid,
                "--request-dir",
                str(request_dir),
                "--response-dir",
                str(response_dir),
            )
            if decrypt.returncode != 0:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "status": "fail",
                        "error": "failed to decrypt response bundles",
                        "prepare_stdout": prepare.stdout,
                        "prepare_stderr": prepare.stderr,
                        "decrypt_stdout": decrypt.stdout,
                        "decrypt_stderr": decrypt.stderr,
                    },
                )
                return

            parsed_results = self._parse_decrypt_stdout(decrypt.stdout)
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "blockchain_state": self._load_blockchain_state(),
                    "prepare_stdout": prepare.stdout,
                    "prepare_stderr": prepare.stderr,
                    "decrypt_stdout": decrypt.stdout,
                    "decrypt_stderr": decrypt.stderr,
                    "results": parsed_results,
                },
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8084)
    parser.add_argument("--role-dir", required=True)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), MduHandler)
    server.role_dir = args.role_dir
    print(f"MDU HTTP service listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
