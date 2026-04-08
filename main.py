from __future__ import annotations

import argparse
import base64
import json
import math
import secrets
import webbrowser
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk
except ImportError:
    tk = None
    filedialog = None
    messagebox = None
    scrolledtext = None
    ttk = None

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
    for field in ("p", "g", "y"):
        payload[field] = int(payload[field])
    return PublicKey(**payload)


def load_private_key(path: Path) -> PrivateKey:
    payload = load_json(path)
    for field in ("p", "g", "y", "x"):
        payload[field] = int(payload[field])
    return PrivateKey(**payload)


def resolve_path(path_text: str, base_dir: Path | None = None) -> Path:
    path = Path(path_text).expanduser()
    if path.is_absolute():
        return path
    return (base_dir or Path.cwd()) / path


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


def save_keypair(output_prefix: Path) -> tuple[Path, Path]:
    public_key, private_key = generate_keypair()
    public_path = output_prefix.with_suffix(".public.json")
    private_path = output_prefix.with_suffix(".private.json")
    dump_json(public_path, asdict(public_key))
    dump_json(private_path, asdict(private_key))
    return public_path, private_path


def handle_genkey(args: argparse.Namespace) -> None:
    output_prefix = Path(args.output)
    public_path, private_path = save_keypair(output_prefix)
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


def launch_gui() -> None:
    if tk is None or ttk is None or filedialog is None or messagebox is None or scrolledtext is None:
        raise RuntimeError("Tkinter khong co san trong moi truong Python hien tai.")

    base_dir = Path.cwd()
    root = tk.Tk()
    root.title("Elsign-2048")
    root.geometry("980x720")
    root.minsize(900, 640)
    root.configure(bg="#f3efe7")

    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    style.configure("App.TFrame", background="#f3efe7")
    style.configure("Card.TLabelframe", background="#f8f5ef", borderwidth=1)
    style.configure("Card.TLabelframe.Label", background="#f8f5ef", foreground="#3f3024")
    style.configure("Title.TLabel", background="#f3efe7", foreground="#2f241b", font=("Georgia", 18, "bold"))
    style.configure("Hint.TLabel", background="#f3efe7", foreground="#6d5f53", font=("Segoe UI", 10))
    style.configure("Action.TButton", font=("Segoe UI", 10, "bold"))

    status_var = tk.StringVar(value="San sang.")
    key_prefix_var = tk.StringVar(value="receiver_key")
    public_key_var = tk.StringVar(value=str(base_dir / "receiver_key.public.json"))
    private_key_var = tk.StringVar(value=str(base_dir / "receiver_key.private.json"))
    cipher_path_var = tk.StringVar(value=str(base_dir / "cipher.json"))
    normalized_var = tk.StringVar(value="")

    def set_status(message: str) -> None:
        status_var.set(message)

    def choose_open_file(target: tk.StringVar, filetypes: list[tuple[str, str]]) -> None:
        selected = filedialog.askopenfilename(
            title="Chon file",
            initialdir=str(base_dir),
            filetypes=filetypes,
        )
        if selected:
            target.set(selected)

    def choose_save_file(target: tk.StringVar, default_ext: str, filetypes: list[tuple[str, str]]) -> None:
        selected = filedialog.asksaveasfilename(
            title="Luu file",
            initialdir=str(base_dir),
            defaultextension=default_ext,
            filetypes=filetypes,
        )
        if selected:
            target.set(selected)

    def refresh_normalized_preview(*_args: object) -> None:
        raw_message = sender_input.get("1.0", "end-1c")
        if not raw_message.strip():
            normalized_var.set("")
            return
        try:
            normalized_var.set(normalize_alpha_message(raw_message))
        except ValueError:
            normalized_var.set("")

    def generate_receiver_keys() -> None:
        try:
            prefix_text = key_prefix_var.get().strip() or "receiver_key"
            output_prefix = resolve_path(prefix_text, base_dir)
            public_path, private_path = save_keypair(output_prefix)
            public_key_var.set(str(public_path))
            private_key_var.set(str(private_path))
            sender_public_entry_var.set(str(public_path))
            receiver_private_entry_var.set(str(private_path))
            set_status(f"Da tao khoa cho ben nhan tai {public_path.name} va {private_path.name}.")
            messagebox.showinfo("Tao khoa", "Da tao khoa cho ben nhan thanh cong.")
        except Exception as exc:
            messagebox.showerror("Loi tao khoa", str(exc))

    def encrypt_for_receiver() -> None:
        try:
            public_key_path = resolve_path(sender_public_entry_var.get().strip(), base_dir)
            output_path = resolve_path(sender_cipher_entry_var.get().strip() or "cipher.json", base_dir)
            message = sender_input.get("1.0", "end-1c")
            public_key = load_public_key(public_key_path)
            ciphertext = encrypt_alpha_message(message, public_key)
            dump_json(output_path, ciphertext)
            normalized = normalize_alpha_message(message)
            normalized_var.set(normalized)
            receiver_cipher_entry_var.set(str(output_path))
            receiver_output.configure(state="normal")
            receiver_output.delete("1.0", "end")
            receiver_output.insert("1.0", "Ban ma da duoc tao. Ben nhan co the mo file nay de giai ma.")
            receiver_output.configure(state="disabled")
            set_status(f"Ben gui da ma hoa va luu ban ma tai {output_path.name}.")
            messagebox.showinfo("Ma hoa", f"Da ma hoa thong diep.\nDang chuan hoa: {normalized}")
        except Exception as exc:
            messagebox.showerror("Loi ma hoa", str(exc))

    def decrypt_for_receiver() -> None:
        try:
            private_key_path = resolve_path(receiver_private_entry_var.get().strip(), base_dir)
            cipher_path = resolve_path(receiver_cipher_entry_var.get().strip(), base_dir)
            private_key = load_private_key(private_key_path)
            ciphertext = load_json(cipher_path)
            if ciphertext.get("encoding") == "alphabet-base26":
                plaintext = decrypt_alpha_message(ciphertext, private_key)
            else:
                plaintext = decrypt_bytes(ciphertext, private_key).decode("utf-8")
            receiver_output.configure(state="normal")
            receiver_output.delete("1.0", "end")
            receiver_output.insert("1.0", plaintext)
            receiver_output.configure(state="disabled")
            set_status(f"Ben nhan da giai ma thanh cong tu {cipher_path.name}.")
        except Exception as exc:
            messagebox.showerror("Loi giai ma", str(exc))

    header = ttk.Frame(root, style="App.TFrame", padding=(22, 18, 22, 8))
    header.pack(fill="x")
    ttk.Label(header, text="Elsign-2048 cho Ben Gui / Ben Nhan", style="Title.TLabel").pack(anchor="w")
    ttk.Label(
        header,
        text="Thong diep van ban se duoc doi thanh chu in hoa A-Z va so hoa theo co so 26 truoc khi ma hoa.",
        style="Hint.TLabel",
    ).pack(anchor="w", pady=(6, 0))

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=18, pady=10)

    sender_tab = ttk.Frame(notebook, style="App.TFrame", padding=18)
    receiver_tab = ttk.Frame(notebook, style="App.TFrame", padding=18)
    help_tab = ttk.Frame(notebook, style="App.TFrame", padding=18)
    notebook.add(receiver_tab, text="Ben Nhan")
    notebook.add(sender_tab, text="Ben Gui")
    notebook.add(help_tab, text="Huong Dan")

    key_card = ttk.LabelFrame(receiver_tab, text="1. Tao khoa cho ben nhan", style="Card.TLabelframe", padding=16)
    key_card.pack(fill="x", pady=(0, 14))
    ttk.Label(key_card, text="Tien to ten khoa:").grid(row=0, column=0, sticky="w")
    ttk.Entry(key_card, textvariable=key_prefix_var, width=42).grid(row=0, column=1, sticky="ew", padx=(10, 10))
    ttk.Button(key_card, text="Tao khoa", style="Action.TButton", command=generate_receiver_keys).grid(row=0, column=2, sticky="ew")
    ttk.Label(key_card, text="Khoa cong khai:").grid(row=1, column=0, sticky="w", pady=(12, 0))
    ttk.Entry(key_card, textvariable=public_key_var).grid(row=1, column=1, columnspan=2, sticky="ew", padx=(10, 0), pady=(12, 0))
    ttk.Label(key_card, text="Khoa bi mat:").grid(row=2, column=0, sticky="w", pady=(10, 0))
    ttk.Entry(key_card, textvariable=private_key_var).grid(row=2, column=1, columnspan=2, sticky="ew", padx=(10, 0), pady=(10, 0))
    key_card.columnconfigure(1, weight=1)

    decrypt_card = ttk.LabelFrame(receiver_tab, text="2. Giai ma cho ben nhan", style="Card.TLabelframe", padding=16)
    decrypt_card.pack(fill="both", expand=True)
    receiver_private_entry_var = tk.StringVar(value=private_key_var.get())
    receiver_cipher_entry_var = tk.StringVar(value=cipher_path_var.get())
    ttk.Label(decrypt_card, text="Khoa bi mat:").grid(row=0, column=0, sticky="w")
    ttk.Entry(decrypt_card, textvariable=receiver_private_entry_var).grid(row=0, column=1, sticky="ew", padx=(10, 10))
    ttk.Button(
        decrypt_card,
        text="Mo khoa",
        command=lambda: choose_open_file(receiver_private_entry_var, [("JSON", "*.json"), ("All files", "*.*")]),
    ).grid(row=0, column=2, sticky="ew")
    ttk.Label(decrypt_card, text="File ban ma:").grid(row=1, column=0, sticky="w", pady=(10, 0))
    ttk.Entry(decrypt_card, textvariable=receiver_cipher_entry_var).grid(row=1, column=1, sticky="ew", padx=(10, 10), pady=(10, 0))
    ttk.Button(
        decrypt_card,
        text="Mo ban ma",
        command=lambda: choose_open_file(receiver_cipher_entry_var, [("JSON", "*.json"), ("All files", "*.*")]),
    ).grid(row=1, column=2, sticky="ew", pady=(10, 0))
    ttk.Button(decrypt_card, text="Giai ma", style="Action.TButton", command=decrypt_for_receiver).grid(
        row=2, column=0, columnspan=3, sticky="ew", pady=(14, 12)
    )
    receiver_output = scrolledtext.ScrolledText(
        decrypt_card,
        height=12,
        wrap="word",
        font=("Consolas", 11),
        bg="#fffdf8",
        fg="#2d241b",
        relief="flat",
    )
    receiver_output.grid(row=3, column=0, columnspan=3, sticky="nsew")
    receiver_output.configure(state="disabled")
    decrypt_card.columnconfigure(1, weight=1)
    decrypt_card.rowconfigure(3, weight=1)

    sender_card = ttk.LabelFrame(sender_tab, text="Ma hoa thong diep cho ben nhan", style="Card.TLabelframe", padding=16)
    sender_card.pack(fill="both", expand=True)
    sender_public_entry_var = tk.StringVar(value=public_key_var.get())
    sender_cipher_entry_var = tk.StringVar(value=cipher_path_var.get())
    ttk.Label(sender_card, text="Khoa cong khai cua ben nhan:").grid(row=0, column=0, sticky="w")
    ttk.Entry(sender_card, textvariable=sender_public_entry_var).grid(row=0, column=1, sticky="ew", padx=(10, 10))
    ttk.Button(
        sender_card,
        text="Mo khoa",
        command=lambda: choose_open_file(sender_public_entry_var, [("JSON", "*.json"), ("All files", "*.*")]),
    ).grid(row=0, column=2, sticky="ew")
    ttk.Label(sender_card, text="Thong diep goc:").grid(row=1, column=0, sticky="nw", pady=(12, 0))
    sender_input = scrolledtext.ScrolledText(
        sender_card,
        height=12,
        wrap="word",
        font=("Consolas", 11),
        bg="#fffdf8",
        fg="#2d241b",
        relief="flat",
    )
    sender_input.grid(row=1, column=1, columnspan=2, sticky="nsew", pady=(12, 0))
    sender_input.bind("<KeyRelease>", refresh_normalized_preview)
    ttk.Label(sender_card, text="Thong diep sau chuan hoa A-Z:").grid(row=2, column=0, sticky="w", pady=(12, 0))
    ttk.Entry(sender_card, textvariable=normalized_var, state="readonly").grid(
        row=2, column=1, columnspan=2, sticky="ew", padx=(10, 0), pady=(12, 0)
    )
    ttk.Label(sender_card, text="File ban ma dau ra:").grid(row=3, column=0, sticky="w", pady=(12, 0))
    ttk.Entry(sender_card, textvariable=sender_cipher_entry_var).grid(row=3, column=1, sticky="ew", padx=(10, 10), pady=(12, 0))
    ttk.Button(
        sender_card,
        text="Luu tai",
        command=lambda: choose_save_file(sender_cipher_entry_var, ".json", [("JSON", "*.json"), ("All files", "*.*")]),
    ).grid(row=3, column=2, sticky="ew", pady=(12, 0))
    ttk.Button(sender_card, text="Ma hoa", style="Action.TButton", command=encrypt_for_receiver).grid(
        row=4, column=0, columnspan=3, sticky="ew", pady=(16, 0)
    )
    sender_card.columnconfigure(1, weight=1)
    sender_card.rowconfigure(1, weight=1)

    guide_card = ttk.LabelFrame(help_tab, text="Quy trinh de xuat", style="Card.TLabelframe", padding=16)
    guide_card.pack(fill="both", expand=True)
    guide_text = scrolledtext.ScrolledText(
        guide_card,
        height=18,
        wrap="word",
        font=("Consolas", 11),
        bg="#fffdf8",
        fg="#2d241b",
        relief="flat",
    )
    guide_text.pack(fill="both", expand=True)
    guide_text.insert(
        "1.0",
        (
            "1. Ben nhan vao tab 'Ben Nhan' va tao cap khoa.\n"
            "2. Gui file khoa cong khai cho ben gui.\n"
            "3. Ben gui vao tab 'Ben Gui', nhap thong diep va ma hoa.\n"
            "4. Ben nhan mo file ban ma va giai ma.\n\n"
            "Luu y:\n"
            "- Thong diep van ban se bi chuan hoa: doi thanh chu in hoa va chi giu A-Z.\n"
            "- Vi du 'Xin chao 2026' se thanh 'XINCHAO'.\n"
            "- GUI nay tap trung cho luong gui/nhan thong diep; chuc nang ky so van co the dung bang CLI.\n"
        ),
    )
    guide_text.configure(state="disabled")

    status_bar = ttk.Label(root, textvariable=status_var, anchor="w", style="Hint.TLabel")
    status_bar.pack(fill="x", padx=20, pady=(0, 16))

    root.mainloop()


def handle_gui(_args: argparse.Namespace) -> None:
    launch_gui()


def handle_web(args: argparse.Namespace) -> None:
    from web_app import run_server

    url = f"http://{args.host}:{args.port}"
    if getattr(args, "open_browser", True):
        webbrowser.open(url)
    run_server(host=args.host, port=args.port)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Elsign-2048: app ma hoa, giai ma va ky so ElGamal 2048-bit."
    )
    subparsers = parser.add_subparsers(dest="command")

    genkey = subparsers.add_parser("genkey", help="Tao cap khoa cho Elsign-2048.")
    genkey.add_argument(
        "-o",
        "--output",
        default="elsign_2048",
        help="Tien to ten file output, mac dinh la elsign_2048.",
    )
    genkey.set_defaults(func=handle_genkey)

    gui = subparsers.add_parser("gui", help="Mo giao dien desktop cho ben gui/ben nhan.")
    gui.set_defaults(func=handle_gui)

    web = subparsers.add_parser("web", help="Chay frontend web Elsign-2048 tren localhost.")
    web.add_argument("--host", default="127.0.0.1", help="Dia chi host, mac dinh la 127.0.0.1.")
    web.add_argument("--port", type=int, default=8000, help="Cong web, mac dinh la 8000.")
    web.add_argument(
        "--no-browser",
        action="store_false",
        dest="open_browser",
        help="Khong tu dong mo trinh duyet khi chay web Elsign-2048.",
    )
    web.set_defaults(func=handle_web)

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
    print("=== Elsign-2048: Ben Gui / Ben Nhan ===")
    print("1. Ben nhan tao khoa")
    print("2. Ben gui ma hoa thong diep")
    print("3. Ben nhan giai ma thong diep")
    print("4. Ky thong diep")
    print("5. Kiem tra chu ky")
    print("6. Mo giao dien desktop")
    print("7. Chay frontend web")
    choice = input("Chon chuc nang (1-7): ").strip()

    try:
        if choice == "1":
            prefix = input("Nhap tien to ten file khoa [elsign_2048]: ").strip() or "elsign_2048"
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
        elif choice == "6":
            launch_gui()
        elif choice == "7":
            handle_web(argparse.Namespace(host="127.0.0.1", port=8000))
        else:
            print("Lua chon khong hop le.")
    except Exception as exc:
        print(f"Loi: {exc}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        handle_web(argparse.Namespace(host="127.0.0.1", port=8000, open_browser=True))
        return
    try:
        args.func(args)
    except Exception as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
