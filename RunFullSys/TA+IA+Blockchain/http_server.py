#!/usr/bin/env python3
import argparse
import base64
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
from urllib.parse import urlparse


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


def make_tar_bytes(base: Path, members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for relative in members:
            path = base / relative
            if path.exists():
                tar.add(path, arcname=relative)
    return buffer.getvalue()


def tar_directory_bytes(directory: Path) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for child in sorted(directory.iterdir()):
            tar.add(child, arcname=child.name)
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

    @property
    def runtime_dir(self) -> Path:
        return self.app_dir / "runtime"

    @property
    def build_dir(self) -> Path:
        return self.app_dir / "build-wsl"

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

    def _read_base64(self, path_str: str):
        path = Path(path_str)
        if not path_str or not path.exists():
            return ""
        return base64.b64encode(path.read_bytes()).decode("ascii")

    def _load_blockchain_state(self):
        state_path = self.runtime_dir / "state" / "blockchain_state.txt"
        values = load_key_values(state_path)
        return {
            "epoch": int(values.get("epoch", "0")),
            "registration_root": values.get("registration_root", ""),
            "revocation_root": values.get("revocation_root", ""),
        }

    def _load_cloud_rekey_state(self):
        values = load_key_values(self.runtime_dir / "cloud" / "rekey_state.txt")
        if not values:
            return None
        return {
            "epoch": int(values.get("epoch", "0")),
            "re_encryption_key": values.get("re_encryption_key", ""),
            "update_token_seed": values.get("update_token_seed", ""),
            "revoked_user_gid": values.get("revoked_user_gid", ""),
        }

    def _load_mobile_user_package(self, gid: str):
        cred_path = self.runtime_dir / "users" / f"{gid}.cred"
        cred_values = load_key_values(cred_path)
        if not cred_values:
            return None

        user_key_path = self.runtime_dir / "users" / f"{gid}_userkey.bin"
        user_key_b64 = ""
        if user_key_path.exists():
            user_key_b64 = base64.b64encode(user_key_path.read_bytes()).decode("ascii")

        attributes = [item for item in cred_values.get("attributes", "").split(",") if item]
        return {
            "gid": cred_values.get("gid", gid),
            "identity_secret": int(cred_values.get("identity_secret", "0")),
            "local_epoch": int(cred_values.get("local_epoch", "0")),
            "attributes": attributes,
            "user_key_base64": user_key_b64,
        }

    def _read_runtime_base64(self, relative_path: str):
        path = self.runtime_dir / relative_path
        if not path.exists():
            return ""
        return base64.b64encode(path.read_bytes()).decode("ascii")

    def _augment_request_dir(self, request_dir: Path):
        verification_key = self.app_dir / "zk" / "build" / "setup" / "verification_key.json"
        if verification_key.exists() and verification_key.is_file():
            shutil.copy2(verification_key, request_dir / "verification_key.json")

    def _auth_input_file_path(self, auth_token_values):
        proof_file_path = (auth_token_values.get("proof_file_path") or "").strip()
        if not proof_file_path:
            return ""
        input_file_path = Path(proof_file_path).with_name("input.json")
        return str(input_file_path) if input_file_path.exists() and input_file_path.is_file() else ""

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
            "auth_token_base64": self._read_base64(str(auth_token_path)),
            "shortlist_trapdoor_base64": self._read_base64(str(shortlist_path)),
            "prover_state_base64": self._read_base64(auth_token_values.get("prover_state_path", "")),
            "input_file_base64": self._read_base64(self._auth_input_file_path(auth_token_values)),
            "proof_file_base64": self._read_base64(auth_token_values.get("proof_file_path", "")),
            "public_file_base64": self._read_base64(auth_token_values.get("public_file_path", "")),
        }

    def _load_mobile_auth_package(self, request_dir: Path):
        auth_token_path = request_dir / "auth_token.txt"
        preferred_label_path = request_dir / "preferred_label.txt"
        gid_path = request_dir / "gid.txt"

        auth_token_values = load_key_values(auth_token_path)
        if not auth_token_values:
            return None

        preferred_label = preferred_label_path.read_text(encoding="utf-8").strip() if preferred_label_path.exists() else ""
        gid = gid_path.read_text(encoding="utf-8").strip() if gid_path.exists() else auth_token_values.get("user_gid", "")

        return {
            "gid": gid,
            "preferred_label": preferred_label,
            "auth_token": auth_token_values,
            "auth_token_base64": self._read_base64(str(auth_token_path)),
            "prover_state_base64": self._read_base64(auth_token_values.get("prover_state_path", "")),
            "input_file_base64": self._read_base64(self._auth_input_file_path(auth_token_values)),
        }

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if parsed.path == "/mobile/state":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "blockchain_state": self._load_blockchain_state(),
                    "cloud_rekey_state": self._load_cloud_rekey_state(),
                },
            )
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

        if parsed.path == "/mobile/register":
            gid = (payload.get("gid") or "").strip()
            attributes = payload.get("attributes") or []
            if not gid:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: gid"})
                return
            if not isinstance(attributes, list) or not all(isinstance(item, str) and item.strip() for item in attributes):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "attributes must be a non-empty string list"})
                return

            args = ["register-raw", gid, *[item.strip() for item in attributes]]
            result = self._run_script(*args)
            if result.returncode != 0:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "status": "fail",
                        "command": args,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    },
                )
                return

            user_package = self._load_mobile_user_package(gid)
            if user_package is None:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "status": "fail",
                        "error": f"registration succeeded but no credential package found for {gid}",
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
                    "user": user_package,
                    "phase1_params_base64": self._read_runtime_base64("abse/phase1_params.txt"),
                    "blockchain_state": self._load_blockchain_state(),
                    "cloud_rekey_state": self._load_cloud_rekey_state(),
                },
            )
            return

        if parsed.path == "/mobile/refresh":
            gid = (payload.get("gid") or "").strip()
            if not gid:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: gid"})
                return

            args = ["refresh-raw", gid]
            result = self._run_script(*args)
            if result.returncode != 0:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "status": "fail",
                        "command": args,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    },
                )
                return

            user_package = self._load_mobile_user_package(gid)
            if user_package is None:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "status": "fail",
                        "error": f"refresh succeeded but no credential package found for {gid}",
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
                    "user": user_package,
                    "phase1_params_base64": self._read_runtime_base64("abse/phase1_params.txt"),
                    "blockchain_state": self._load_blockchain_state(),
                    "cloud_rekey_state": self._load_cloud_rekey_state(),
                },
            )
            return

        if parsed.path == "/mobile/revoke":
            revoked_gid = (payload.get("revoked_gid") or payload.get("target_gid") or payload.get("gid") or "").strip()
            if not revoked_gid:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: revoked_gid"})
                return

            args = ["revoke-raw", revoked_gid]
            result = self._run_script(*args)
            if result.returncode != 0:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "status": "fail",
                        "command": args,
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
                    "revoked_gid": revoked_gid,
                    "blockchain_state": self._load_blockchain_state(),
                    "cloud_rekey_state": self._load_cloud_rekey_state(),
                },
            )
            return

        if parsed.path == "/mobile/prepare-query":
            gid = (payload.get("gid") or "").strip()
            preferred_label = (payload.get("preferred_label") or payload.get("label") or "").strip()
            keywords = payload.get("keywords") or []
            if not gid:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: gid"})
                return
            if not isinstance(keywords, list) or not all(isinstance(item, str) and item.strip() for item in keywords):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "keywords must be a non-empty string list"})
                return

            with tempfile.TemporaryDirectory(prefix="pqabse-mobile-query-") as temp_dir_name:
                request_dir = Path(temp_dir_name) / "request"
                request_dir.mkdir()
                args = ["prepare-query-dir", gid, str(request_dir), preferred_label, *[item.strip() for item in keywords]]
                result = self._run_script(*args)
                if result.returncode != 0:
                    self._send_json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {
                            "status": "fail",
                            "command": args,
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                        },
                    )
                    return

                query_package = self._load_mobile_query_package(request_dir)
                if query_package is None:
                    self._send_json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {
                            "status": "fail",
                            "error": f"query preparation succeeded but no mobile query package was found for {gid}",
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                        },
                    )
                    return

                self._augment_request_dir(request_dir)
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "status": "ok",
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "query_package": query_package,
                        "request_archive_base64": base64.b64encode(tar_directory_bytes(request_dir)).decode("ascii"),
                        "phase1_params_base64": self._read_runtime_base64("abse/phase1_params.txt"),
                        "blockchain_state": self._load_blockchain_state(),
                        "cloud_rekey_state": self._load_cloud_rekey_state(),
                    },
                )
            return

        if parsed.path == "/mobile/prepare-auth":
            gid = (payload.get("gid") or "").strip()
            preferred_label = (payload.get("preferred_label") or payload.get("label") or "").strip()
            if not gid:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing field: gid"})
                return

            with tempfile.TemporaryDirectory(prefix="pqabse-mobile-auth-") as temp_dir_name:
                request_dir = Path(temp_dir_name) / "request"
                request_dir.mkdir()
                args = ["prepare-auth-dir", gid, str(request_dir), preferred_label]
                result = self._run_script(*args)
                if result.returncode != 0:
                    self._send_json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {
                            "status": "fail",
                            "command": args,
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                        },
                    )
                    return

                auth_package = self._load_mobile_auth_package(request_dir)
                if auth_package is None:
                    self._send_json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {
                            "status": "fail",
                            "error": f"auth preparation succeeded but no mobile auth package was found for {gid}",
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                        },
                    )
                    return

                self._augment_request_dir(request_dir)
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "status": "ok",
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "auth_package": auth_package,
                        "verification_key_base64": self._read_base64(str(request_dir / "verification_key.json")),
                        "phase1_params_base64": self._read_runtime_base64("abse/phase1_params.txt"),
                        "blockchain_state": self._load_blockchain_state(),
                        "cloud_rekey_state": self._load_cloud_rekey_state(),
                    },
                )
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
