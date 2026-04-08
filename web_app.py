from __future__ import annotations

import json
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from main import (
    PrivateKey,
    PublicKey,
    decrypt_alpha_message,
    encrypt_alpha_message,
    generate_keypair,
    normalize_alpha_message,
)


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "web"


def serialize_key(key: PublicKey | PrivateKey) -> dict[str, Any]:
    payload = asdict(key)
    for field in ("p", "g", "y", "x"):
        if field in payload:
            payload[field] = str(payload[field])
    return payload


def parse_public_key(payload: dict[str, Any]) -> PublicKey:
    normalized = dict(payload)
    for field in ("p", "g", "y"):
        normalized[field] = int(normalized[field])
    return PublicKey(**normalized)


def parse_private_key(payload: dict[str, Any]) -> PrivateKey:
    normalized = dict(payload)
    for field in ("p", "g", "y", "x"):
        normalized[field] = int(normalized[field])
    return PrivateKey(**normalized)


class ElsignWebHandler(BaseHTTPRequestHandler):
    server_version = "ElsignWeb/1.0"

    def do_GET(self) -> None:
        if self.path in {"/", "/index.html", "/receiver", "/receiver.html"}:
            self._serve_file(FRONTEND_DIR / "receiver.html", "text/html; charset=utf-8")
            return
        if self.path in {"/sender", "/sender.html"}:
            self._serve_file(FRONTEND_DIR / "sender.html", "text/html; charset=utf-8")
            return
        if self.path == "/styles.css":
            self._serve_file(FRONTEND_DIR / "styles.css", "text/css; charset=utf-8")
            return
        if self.path == "/app.js":
            self._serve_file(FRONTEND_DIR / "app.js", "application/javascript; charset=utf-8")
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Khong tim thay tai nguyen.")

    def do_POST(self) -> None:
        try:
            payload = self._read_json()
            if self.path == "/api/generate-keys":
                self._handle_generate_keys()
                return
            if self.path == "/api/encrypt":
                self._handle_encrypt(payload)
                return
            if self.path == "/api/decrypt":
                self._handle_decrypt(payload)
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Khong tim thay API.")
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except json.JSONDecodeError:
            self._send_json({"error": "Du lieu JSON khong hop le."}, status=HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            self._send_json({"error": f"Loi may chu: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _serve_file(self, path: Path, content_type: str) -> None:
        if not path.exists():
            self.send_error(HTTPStatus.NOT_FOUND, "Khong tim thay file.")
            return
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def _handle_generate_keys(self) -> None:
        public_key, private_key = generate_keypair()
        self._send_json(
            {
                "public_key": serialize_key(public_key),
                "private_key": serialize_key(private_key),
            }
        )

    def _handle_encrypt(self, payload: dict[str, Any]) -> None:
        message = str(payload.get("message", ""))
        public_key_payload = payload.get("public_key")
        if not isinstance(public_key_payload, dict):
            raise ValueError("Can cung cap public_key hop le.")
        public_key = parse_public_key(public_key_payload)
        ciphertext = encrypt_alpha_message(message, public_key)
        self._send_json(
            {
                "normalized": normalize_alpha_message(message),
                "ciphertext": ciphertext,
            }
        )

    def _handle_decrypt(self, payload: dict[str, Any]) -> None:
        private_key_payload = payload.get("private_key")
        ciphertext_payload = payload.get("ciphertext")
        if not isinstance(private_key_payload, dict):
            raise ValueError("Can cung cap private_key hop le.")
        if not isinstance(ciphertext_payload, dict):
            raise ValueError("Can cung cap ciphertext hop le.")
        private_key = parse_private_key(private_key_payload)
        plaintext = decrypt_alpha_message(ciphertext_payload, private_key)
        self._send_json({"plaintext": plaintext})

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), ElsignWebHandler)
    print(f"Elsign-2048 web app dang chay tai http://{host}:{port}")
    print("Nhan Ctrl+C de dung server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDa dung server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
