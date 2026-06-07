from __future__ import annotations

import json
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import base64
from main import (
    PrivateKey,
    PublicKey,
    decrypt_alpha_message,
    encrypt_alpha_message,
    decrypt_bytes,
    encrypt_bytes,
    encrypt_file_hybrid,
    decrypt_file_hybrid,
    generate_keypair,
    normalize_alpha_message,
    sign_bytes,
    verify_signature,
)


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "web"


def stringify_bigints(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: stringify_bigints(v) for k, v in obj.items()}
    elif isinstance(obj, int):
        return str(obj)
    return obj

def parse_bigints(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: parse_bigints(v) for k, v in obj.items()}
    elif isinstance(obj, str) and obj.isdigit():
        return int(obj)
    return obj

def serialize_key(key: PublicKey | PrivateKey) -> dict[str, Any]:
    payload = asdict(key)
    for field in ("p", "g", "y", "x"):
        if field in payload:
            payload[field] = str(payload[field])
    if payload.get("prime_certificate"):
        payload["prime_certificate"] = stringify_bigints(payload["prime_certificate"])
    else:
        if "prime_certificate" in payload:
            del payload["prime_certificate"]
    return payload


def parse_public_key(payload: dict[str, Any]) -> PublicKey:
    normalized = dict(payload)
    for field in ("p", "g", "y"):
        normalized[field] = int(normalized[field])
    if "prime_certificate" in normalized and normalized["prime_certificate"]:
        normalized["prime_certificate"] = parse_bigints(normalized["prime_certificate"])
    return PublicKey(**normalized)


def parse_private_key(payload: dict[str, Any]) -> PrivateKey:
    normalized = dict(payload)
    for field in ("p", "g", "y", "x"):
        normalized[field] = int(normalized[field])
    if "prime_certificate" in normalized and normalized["prime_certificate"]:
        normalized["prime_certificate"] = parse_bigints(normalized["prime_certificate"])
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
                self._handle_generate_keys(payload)
                return
            if self.path == "/api/encrypt":
                self._handle_encrypt(payload)
                return
            if self.path == "/api/decrypt":
                self._handle_decrypt(payload)
                return
            if self.path == "/api/sign":
                self._handle_sign(payload)
                return
            if self.path == "/api/verify":
                self._handle_verify(payload)
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

    def _handle_generate_keys(self, payload: dict[str, Any]) -> None:
        prime_mode = int(payload.get("prime_mode", 2))
        public_key, private_key = generate_keypair(prime_mode)
        self._send_json(
            {
                "public_key": serialize_key(public_key),
                "private_key": serialize_key(private_key),
            }
        )

    def _handle_encrypt(self, payload: dict[str, Any]) -> None:
        public_key_payload = payload.get("public_key")
        if not isinstance(public_key_payload, dict):
            raise ValueError("Can cung cap public_key hop le.")
        public_key = parse_public_key(public_key_payload)
        
        file_base64 = payload.get("file_base64")
        if file_base64:
            file_bytes = base64.b64decode(file_base64)
            ciphertext = encrypt_file_hybrid(
                file_bytes,
                public_key,
                original_filename=str(payload.get("file_name") or ""),
                mime_type=str(payload.get("mime_type") or ""),
            )
            self._send_json({
                "is_file": True,
                "ciphertext": ciphertext,
            })
            return

        message = str(payload.get("message", ""))
        ciphertext = encrypt_alpha_message(message, public_key)
        self._send_json(
            {
                "normalized": normalize_alpha_message(message),
                "ciphertext": ciphertext,
                "is_file": False,
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
        
        if ciphertext_payload.get("encoding") == "hybrid-hex":
            plaintext_bytes = decrypt_file_hybrid(ciphertext_payload, private_key)
            self._send_json({
                "is_file": True,
                "file_base64": base64.b64encode(plaintext_bytes).decode("ascii"),
                "file_name": ciphertext_payload.get("original_filename") or "decrypted_file.bin",
                "mime_type": ciphertext_payload.get("mime_type") or "application/octet-stream",
            })
            return
        elif ciphertext_payload.get("encoding") == "hex-blocks":
            plaintext_bytes = decrypt_bytes(ciphertext_payload, private_key)
            self._send_json({
                "is_file": True,
                "file_base64": base64.b64encode(plaintext_bytes).decode("ascii"),
                "file_name": ciphertext_payload.get("original_filename") or "decrypted_file.bin",
                "mime_type": ciphertext_payload.get("mime_type") or "application/octet-stream",
            })
            return

        plaintext = decrypt_alpha_message(ciphertext_payload, private_key)
        self._send_json({"plaintext": plaintext, "is_file": False})

    def _handle_sign(self, payload: dict[str, Any]) -> None:
        private_key_payload = payload.get("private_key")
        if not isinstance(private_key_payload, dict):
            raise ValueError("Can cung cap private_key hop le.")
        private_key = parse_private_key(private_key_payload)

        file_base64 = payload.get("file_base64")
        if file_base64:
            message_bytes = base64.b64decode(file_base64)
        else:
            message = str(payload.get("message", ""))
            message_bytes = message.encode("utf-8")

        signature = sign_bytes(message_bytes, private_key)
        self._send_json({"signature": signature})

    def _handle_verify(self, payload: dict[str, Any]) -> None:
        public_key_payload = payload.get("public_key")
        signature = payload.get("signature")
        if not isinstance(public_key_payload, dict):
            raise ValueError("Can cung cap public_key hop le.")
        if not isinstance(signature, dict):
            raise ValueError("Can cung cap signature hop le.")
        
        public_key = parse_public_key(public_key_payload)

        file_base64 = payload.get("file_base64")
        if file_base64:
            message_bytes = base64.b64decode(file_base64)
        else:
            message = str(payload.get("message", ""))
            message_bytes = message.encode("utf-8")

        is_valid = verify_signature(message_bytes, signature, public_key)
        self._send_json({"is_valid": is_valid})

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), ElsignWebHandler)
    browser_host = "127.0.0.1" if host == "0.0.0.0" else host
    print(f"Elsign-2048 web app dang chay tai http://{browser_host}:{port}")
    if host == "0.0.0.0":
        print(f"Server dang lang nghe tren moi interface: http://{host}:{port}")
    print("Nhan Ctrl+C de dung server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDa dung server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    run_server(host="0.0.0.0", port=port)
