from __future__ import annotations

import argparse
import base64
import json
import math
import secrets
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
    "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F"
    "A5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C"
    "62F356208552BB9ED529077096966D670C354E4ABC9804F174"
    "6C08CA18217C32905E462E36CE3BE39E772C180E86039B2783"
    "A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497C"
    "EA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF"
    "FFFFFFFF"
)

P = int(P_HEX, 16)
G = 2
BLOCK_SIZE = (P.bit_length() - 1) // 8
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_BASE = len(ALPHABET)


def max_alpha_block_size() -> int:
    size = 0
    value = 1
    while value * ALPHABET_BASE < P:
        value *= ALPHABET_BASE
        size += 1
    return size


ALPHA_BLOCK_SIZE = max_alpha_block_size()


@dataclass
class PublicKey:
    p: int
    g: int
    y: int
    bits: int
    block_size: int


@dataclass
class PrivateKey:
    p: int
    g: int
    y: int
    x: int
    bits: int
    block_size: int


def mod_inverse(value: int, modulus: int) -> int:
    return pow(value, -1, modulus)


def random_coprime(modulus: int) -> int:
    while True:
        candidate = secrets.randbelow(modulus - 3) + 2
        if math.gcd(candidate, modulus) == 1:
            return candidate


def generate_keypair() -> tuple[PublicKey, PrivateKey]:
    x = secrets.randbelow(P - 3) + 2
    y = pow(G, x, P)
    public_key = PublicKey(p=P, g=G, y=y, bits=P.bit_length(), block_size=BLOCK_SIZE)
    private_key = PrivateKey(
        p=P,
        g=G,
        y=y,
        x=x,
        bits=P.bit_length(),
        block_size=BLOCK_SIZE,
    )
    return public_key, private_key


def normalize_alpha_message(message: str) -> str:
    normalized = "".join(char for char in message.upper() if char in ALPHABET)
    if not normalized:
        raise ValueError("Thong diep phai co it nhat mot ky tu tu A den Z sau khi chuan hoa.")
    return normalized


def alpha_block_to_int(block: str) -> int:
    value = 0
    for char in block:
        value = value * ALPHABET_BASE + ALPHABET.index(char)
    return value


def int_to_alpha_block(value: int, length: int) -> str:
    chars = ["A"] * length
    for index in range(length - 1, -1, -1):
        value, digit = divmod(value, ALPHABET_BASE)
        chars[index] = ALPHABET[digit]
    return "".join(chars)


def encrypt_alpha_message(message: str, public_key: PublicKey) -> dict[str, Any]:
    normalized = normalize_alpha_message(message)
    blocks: list[dict[str, str | int]] = []
    for index in range(0, len(normalized), ALPHA_BLOCK_SIZE):
        block = normalized[index : index + ALPHA_BLOCK_SIZE]
        m = alpha_block_to_int(block)
        k = random_coprime(public_key.p - 1)
        a = pow(public_key.g, k, public_key.p)
        b = (m * pow(public_key.y, k, public_key.p)) % public_key.p
        blocks.append({"a": format(a, "x"), "b": format(b, "x"), "chars": len(block)})
    return {
        "algorithm": "ElGamal-2048",
        "encoding": "alphabet-base26",
        "alphabet": ALPHABET,
        "char_block_size": ALPHA_BLOCK_SIZE,
        "blocks": blocks,
    }


def decrypt_alpha_message(ciphertext: dict[str, Any], private_key: PrivateKey) -> str:
    plaintext_blocks: list[str] = []
    for block in ciphertext["blocks"]:
        a = int(block["a"], 16)
        b = int(block["b"], 16)
        char_count = int(block["chars"])
        shared_secret = pow(a, private_key.x, private_key.p)
        m = (b * mod_inverse(shared_secret, private_key.p)) % private_key.p
        plaintext_blocks.append(int_to_alpha_block(m, char_count))
    return "".join(plaintext_blocks)


def encrypt_bytes(plaintext: bytes, public_key: PublicKey) -> dict[str, Any]:
    blocks: list[dict[str, str | int]] = []
    for index in range(0, len(plaintext), public_key.block_size):
        chunk = plaintext[index : index + public_key.block_size]
        m = int.from_bytes(chunk, "big")
        k = random_coprime(public_key.p - 1)
        a = pow(public_key.g, k, public_key.p)
        b = (m * pow(public_key.y, k, public_key.p)) % public_key.p
        blocks.append({"a": format(a, "x"), "b": format(b, "x"), "length": len(chunk)})
    return {
        "algorithm": "ElGamal-2048",
        "encoding": "hex-blocks",
        "block_size": public_key.block_size,
        "blocks": blocks,
    }


def decrypt_bytes(ciphertext: dict[str, Any], private_key: PrivateKey) -> bytes:
    plaintext = bytearray()
    for block in ciphertext["blocks"]:
        a = int(block["a"], 16)
        b = int(block["b"], 16)
        length = int(block["length"])
        shared_secret = pow(a, private_key.x, private_key.p)
        m = (b * mod_inverse(shared_secret, private_key.p)) % private_key.p
        plaintext.extend(m.to_bytes(length, "big"))
    return bytes(plaintext)


def sign_bytes(message: bytes, private_key: PrivateKey) -> dict[str, Any]:
    h = int.from_bytes(sha256(message).digest(), "big") % (private_key.p - 1)
    k = random_coprime(private_key.p - 1)
    r = pow(private_key.g, k, private_key.p)
    s = ((h - private_key.x * r) * mod_inverse(k, private_key.p - 1)) % (private_key.p - 1)
    return {
        "algorithm": "ElGamal-Signature-2048",
        "hash": "SHA-256",
        "r": format(r, "x"),
        "s": format(s, "x"),
    }


def verify_signature(message: bytes, signature: dict[str, Any], public_key: PublicKey) -> bool:
    r = int(signature["r"], 16)
    s = int(signature["s"], 16)
    if not 0 < r < public_key.p:
        return False
    h = int.from_bytes(sha256(message).digest(), "big") % (public_key.p - 1)
    left = pow(public_key.g, h, public_key.p)
    right = (pow(public_key.y, r, public_key.p) * pow(r, s, public_key.p)) % public_key.p
    return left == right


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def dump_json(path: Path, payload: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)


def load_public_key(path: Path) -> PublicKey:
    payload = load_json(path)
    return PublicKey(**payload)


def load_private_key(path: Path) -> PrivateKey:
    payload = load_json(path)
    return PrivateKey(**payload)


def read_input_bytes(message: str | None, input_file: Path | None) -> bytes:
    if message is not None and input_file is not None:
        raise ValueError("Chi duoc chon --message hoac --infile.")
    if message is None and input_file is None:
        raise ValueError("Can cung cap --message hoac --infile.")
    if message is not None:
        return message.encode("utf-8")
    return input_file.read_bytes()


def write_plain_output(data: bytes, output_file: Path | None, as_text: bool) -> None:
    if output_file is not None:
        output_file.write_bytes(data)
        print(f"Da ghi du lieu ra {output_file}")
        return
    if as_text:
        print(data.decode("utf-8"))
        return
    print(base64.b64encode(data).decode("ascii"))


def write_text_output(text: str, output_file: Path | None) -> None:
    if output_file is not None:
        output_file.write_text(text, encoding="utf-8")
        print(f"Da ghi du lieu ra {output_file}")
        return
    print(text)


def handle_genkey(args: argparse.Namespace) -> None:
    public_key, private_key = generate_keypair()
    output_prefix = Path(args.output)
    public_path = output_prefix.with_suffix(".public.json")
    private_path = output_prefix.with_suffix(".private.json")
    dump_json(public_path, asdict(public_key))
    dump_json(private_path, asdict(private_key))
    print(f"Da tao khoa cong khai: {public_path}")
    print(f"Da tao khoa bi mat: {private_path}")


def handle_encrypt(args: argparse.Namespace) -> None:
    public_key = load_public_key(Path(args.key))
    if args.message is not None:
        ciphertext = encrypt_alpha_message(args.message, public_key)
    else:
        payload = read_input_bytes(args.message, Path(args.infile) if args.infile else None)
        ciphertext = encrypt_bytes(payload, public_key)
    dump_json(Path(args.outfile), ciphertext)
    print(f"Da ghi ban ma vao {args.outfile}")


def handle_decrypt(args: argparse.Namespace) -> None:
    private_key = load_private_key(Path(args.key))
    ciphertext = load_json(Path(args.infile))
    if ciphertext.get("encoding") == "alphabet-base26":
        plaintext = decrypt_alpha_message(ciphertext, private_key)
        write_text_output(plaintext, Path(args.outfile) if args.outfile else None)
        return
    plaintext = decrypt_bytes(ciphertext, private_key)
    write_plain_output(plaintext, Path(args.outfile) if args.outfile else None, args.text)


def handle_sign(args: argparse.Namespace) -> None:
    private_key = load_private_key(Path(args.key))
    payload = read_input_bytes(args.message, Path(args.infile) if args.infile else None)
    signature = sign_bytes(payload, private_key)
    dump_json(Path(args.outfile), signature)
    print(f"Da ghi chu ky vao {args.outfile}")


def handle_verify(args: argparse.Namespace) -> None:
    public_key = load_public_key(Path(args.key))
    payload = read_input_bytes(args.message, Path(args.infile) if args.infile else None)
    signature = load_json(Path(args.signature))
    is_valid = verify_signature(payload, signature, public_key)
    print("Chu ky hop le." if is_valid else "Chu ky khong hop le.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="App ma hoa, giai ma va ky so ElGamal 2048-bit."
    )
    subparsers = parser.add_subparsers(dest="command")

    genkey = subparsers.add_parser("genkey", help="Tao cap khoa ElGamal 2048-bit.")
    genkey.add_argument(
        "-o",
        "--output",
        default="elgamal_2048",
        help="Tien to ten file output, mac dinh la elgamal_2048.",
    )
    genkey.set_defaults(func=handle_genkey)

    encrypt = subparsers.add_parser("encrypt", help="Ma hoa thong diep chu cai hoac file.")
    encrypt.add_argument("--key", required=True, help="Duong dan khoa cong khai JSON.")
    encrypt.add_argument("--message", help="Thong diep duoc chuan hoa ve A-Z va ma hoa theo base 26.")
    encrypt.add_argument("--infile", help="File can ma hoa.")
    encrypt.add_argument("--outfile", required=True, help="File JSON chua ban ma.")
    encrypt.set_defaults(func=handle_encrypt)

    decrypt = subparsers.add_parser("decrypt", help="Giai ma ban ma JSON.")
    decrypt.add_argument("--key", required=True, help="Duong dan khoa bi mat JSON.")
    decrypt.add_argument("--infile", required=True, help="File JSON chua ban ma.")
    decrypt.add_argument("--outfile", help="File dich de ghi du lieu giai ma.")
    decrypt.add_argument(
        "--text",
        action="store_true",
        help="In plaintext ra man hinh duoi dang UTF-8.",
    )
    decrypt.set_defaults(func=handle_decrypt)

    sign = subparsers.add_parser("sign", help="Ky chuoi hoac file.")
    sign.add_argument("--key", required=True, help="Duong dan khoa bi mat JSON.")
    sign.add_argument("--message", help="Chuoi UTF-8 can ky.")
    sign.add_argument("--infile", help="File can ky.")
    sign.add_argument("--outfile", required=True, help="File JSON chua chu ky.")
    sign.set_defaults(func=handle_sign)

    verify = subparsers.add_parser("verify", help="Kiem tra chu ky.")
    verify.add_argument("--key", required=True, help="Duong dan khoa cong khai JSON.")
    verify.add_argument("--signature", required=True, help="File JSON chua chu ky.")
    verify.add_argument("--message", help="Chuoi UTF-8 can kiem tra.")
    verify.add_argument("--infile", help="File can kiem tra.")
    verify.set_defaults(func=handle_verify)

    return parser


def interactive_menu() -> None:
    print("=== ElGamal 2048-bit: Ben Gui / Ben Nhan ===")
    print("1. Ben nhan tao khoa")
    print("2. Ben gui ma hoa thong diep")
    print("3. Ben nhan giai ma thong diep")
    print("4. Ky thong diep")
    print("5. Kiem tra chu ky")
    choice = input("Chon chuc nang (1-5): ").strip()

    try:
        if choice == "1":
            prefix = input("Nhap tien to ten file khoa [elgamal_2048]: ").strip() or "elgamal_2048"
            handle_genkey(argparse.Namespace(output=prefix))
        elif choice == "2":
            key = input("Nhap file khoa cong khai cua ben nhan: ").strip()
            message = input("Nhap thong diep can ma hoa: ")
            outfile = input("Nhap file JSON ban ma [cipher.json]: ").strip() or "cipher.json"
            normalized = normalize_alpha_message(message)
            print(f"Thong diep sau chuan hoa: {normalized}")
            handle_encrypt(argparse.Namespace(key=key, message=message, infile=None, outfile=outfile))
        elif choice == "3":
            key = input("Nhap file khoa bi mat cua ben nhan: ").strip()
            infile = input("Nhap file JSON ban ma [cipher.json]: ").strip() or "cipher.json"
            handle_decrypt(argparse.Namespace(key=key, infile=infile, outfile=None, text=True))
        elif choice == "4":
            key = input("Nhap file khoa bi mat: ").strip()
            message = input("Nhap thong diep can ky: ")
            outfile = input("Nhap file JSON chu ky [signature.json]: ").strip() or "signature.json"
            handle_sign(argparse.Namespace(key=key, message=message, infile=None, outfile=outfile))
        elif choice == "5":
            key = input("Nhap file khoa cong khai: ").strip()
            signature = input("Nhap file JSON chu ky [signature.json]: ").strip() or "signature.json"
            message = input("Nhap thong diep can kiem tra: ")
            handle_verify(
                argparse.Namespace(key=key, signature=signature, message=message, infile=None)
            )
        else:
            print("Lua chon khong hop le.")
    except Exception as exc:
        print(f"Loi: {exc}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        interactive_menu()
        return
    try:
        args.func(args)
    except Exception as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
