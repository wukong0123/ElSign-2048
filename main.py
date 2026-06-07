from __future__ import annotations

import argparse
import base64
import json
import math
import secrets
import struct
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

P_HEX_DEFAULT = (
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

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_BASE = len(ALPHABET)


def max_alpha_block_size(p: int) -> int:
    size = 0
    value = 1
    while value * ALPHABET_BASE < p:
        value *= ALPHABET_BASE
        size += 1
    return size


@dataclass
class PublicKey:
    p: int
    g: int
    y: int
    bits: int
    block_size: int
    prime_certificate: dict[str, Any] | None = None


@dataclass
class PrivateKey:
    p: int
    g: int
    y: int
    x: int
    bits: int
    block_size: int
    prime_certificate: dict[str, Any] | None = None


def mod_inverse(value: int, modulus: int) -> int:
    return pow(value, -1, modulus)


def random_coprime(modulus: int) -> int:
    while True:
        candidate = secrets.randbelow(modulus - 3) + 2
        if math.gcd(candidate, modulus) == 1:
            return candidate


def generate_keypair(prime_mode: int = 2) -> tuple[PublicKey, PrivateKey]:
    import random
    from primes import generate_probable_prime, generate_provable_prime
    
    p = None
    prime_cert = None
    
    if prime_mode == 1:
        p = generate_probable_prime(2048)
    elif prime_mode == 2:
        try:
            pool_path = Path(__file__).parent / "certified_pool.json"
            if not pool_path.exists():
                print("Không tìm thấy certified_pool.json. Tự động sinh ngẫu nhiên.")
                p = generate_probable_prime(2048)
            else:
                with pool_path.open("r", encoding="utf-8") as f:
                    pool = json.load(f)
                choice = random.choice(pool)
                p = choice["p"]
                prime_cert = choice.get("prime_certificate")
        except Exception as e:
            print(f"Lỗi đọc pool: {e}. Chuyển sang sinh ngẫu nhiên.")
            p = generate_probable_prime(2048)
    elif prime_mode == 3:
        p, prime_cert = generate_provable_prime(2048)
    
    if p is None:
        p = int(P_HEX_DEFAULT, 16)
        
    g = 2
    block_size = (p.bit_length() - 1) // 8
    x = secrets.randbelow(p - 3) + 2
    y = pow(g, x, p)
    
    public_key = PublicKey(p=p, g=g, y=y, bits=p.bit_length(), block_size=block_size, prime_certificate=prime_cert)
    private_key = PrivateKey(
        p=p,
        g=g,
        y=y,
        x=x,
        bits=p.bit_length(),
        block_size=block_size,
        prime_certificate=prime_cert,
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
    alpha_block_size = max_alpha_block_size(public_key.p)
    for index in range(0, len(normalized), alpha_block_size):
        block = normalized[index : index + alpha_block_size]
        m = alpha_block_to_int(block)
        k = random_coprime(public_key.p - 1)
        a = pow(public_key.g, k, public_key.p)
        b = (m * pow(public_key.y, k, public_key.p)) % public_key.p
        blocks.append({"a": format(a, "x"), "b": format(b, "x"), "chars": len(block)})
    return {
        "algorithm": "ElGamal-2048",
        "encoding": "alphabet-base26",
        "alphabet": ALPHABET,
        "char_block_size": alpha_block_size,
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


def stream_cipher_sha256_ctr(key: bytes, data: bytes) -> bytes:
    out = bytearray()
    chunk_size = 32
    for i in range(0, len(data), chunk_size):
        counter_bytes = struct.pack(">Q", i // chunk_size)
        keystream = sha256(key + counter_bytes).digest()
        chunk = data[i : i + chunk_size]
        for j in range(len(chunk)):
            out.append(chunk[j] ^ keystream[j])
    return bytes(out)


def encrypt_file_hybrid(
    file_bytes: bytes,
    public_key: PublicKey,
    original_filename: str | None = None,
    mime_type: str | None = None,
) -> dict[str, Any]:
    import os
    sym_key = os.urandom(32)
    ciphertext_bytes = stream_cipher_sha256_ctr(sym_key, file_bytes)
    
    sym_key_int = int.from_bytes(sym_key, "big")
    k = random_coprime(public_key.p - 1)
    a = pow(public_key.g, k, public_key.p)
    b = (sym_key_int * pow(public_key.y, k, public_key.p)) % public_key.p
    
    payload = {
        "algorithm": "Hybrid-ElGamal-SHA256CTR",
        "encoding": "hybrid-hex",
        "encrypted_symmetric_key": {
            "a": format(a, "x"),
            "b": format(b, "x")
        },
        "ciphertext_base64": base64.b64encode(ciphertext_bytes).decode("ascii")
    }
    if original_filename:
        payload["original_filename"] = Path(original_filename).name
    if mime_type:
        payload["mime_type"] = mime_type
    return payload


def decrypt_file_hybrid(ciphertext: dict[str, Any], private_key: PrivateKey) -> bytes:
    enc_sym = ciphertext["encrypted_symmetric_key"]
    a = int(enc_sym["a"], 16)
    b = int(enc_sym["b"], 16)
    
    shared_secret = pow(a, private_key.x, private_key.p)
    sym_key_int = (b * mod_inverse(shared_secret, private_key.p)) % private_key.p
    sym_key = sym_key_int.to_bytes(32, "big")
    
    ciphertext_bytes = base64.b64decode(ciphertext["ciphertext_base64"])
    return stream_cipher_sha256_ctr(sym_key, ciphertext_bytes)

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
    if not 0 <= s < public_key.p - 1:
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


def save_keypair(output_prefix: Path, prime_mode: int = 2) -> tuple[Path, Path]:
    public_key, private_key = generate_keypair(prime_mode)
    public_path = output_prefix.with_suffix(".public.json")
    private_path = output_prefix.with_suffix(".private.json")
    
    pub_dict = asdict(public_key)
    priv_dict = asdict(private_key)
    
    # Remove null certificates to save space
    if pub_dict.get("prime_certificate") is None:
        del pub_dict["prime_certificate"]
    if priv_dict.get("prime_certificate") is None:
        del priv_dict["prime_certificate"]
        
    dump_json(public_path, pub_dict)
    dump_json(private_path, priv_dict)
    return public_path, private_path


def handle_genkey(args: argparse.Namespace) -> None:
    output_prefix = Path(args.output)
    prime_mode = getattr(args, "prime_mode", 2)
    public_path, private_path = save_keypair(output_prefix, prime_mode)
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
    root.configure(bg="#f4f6f8")
    
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    style.configure("App.TFrame", background="#f4f6f8")
    style.configure("Card.TLabelframe", background="#ffffff", borderwidth=0, relief="flat")
    style.configure("Card.TLabelframe.Label", background="#ffffff", foreground="#212b36", font=("Segoe UI", 13, "bold"))
    style.configure("Title.TLabel", background="#f4f6f8", foreground="#212b36", font=("Segoe UI", 24, "bold"))
    style.configure("Hint.TLabel", background="#f4f6f8", foreground="#637381", font=("Segoe UI", 11))
    style.configure("Action.TButton", font=("Segoe UI", 11, "bold"), padding=8)
    style.configure("TLabel", background="#ffffff", font=("Segoe UI", 10))
    style.configure("TRadiobutton", background="#ffffff", font=("Segoe UI", 10))

    status_var = tk.StringVar(value="San sang.")
    key_prefix_var = tk.StringVar(value="receiver_key")
    prime_mode_var = tk.IntVar(value=2)
    public_key_var = tk.StringVar(value=str(base_dir / "receiver_key.public.json"))
    private_key_var = tk.StringVar(value=str(base_dir / "receiver_key.private.json"))
    cipher_path_var = tk.StringVar(value=str(base_dir / "cipher.json"))
    normalized_var = tk.StringVar(value="")
    sender_mode_var = tk.IntVar(value=1)
    sender_file_entry_var = tk.StringVar()

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
        prefix_text = key_prefix_var.get().strip() or "receiver_key"
        output_prefix = resolve_path(prefix_text, base_dir)
        mode = prime_mode_var.get()
        
        def task() -> None:
            try:
                public_path, private_path = save_keypair(output_prefix, prime_mode=mode)
                root.after(0, lambda: on_keys_generated(public_path, private_path))
            except Exception as exc:
                root.after(0, lambda e=exc: messagebox.showerror("Loi tao khoa", str(e)))
                root.after(0, lambda: set_status("Lỗi khi tạo khóa."))
                root.after(0, progress_bar.stop)
                root.after(0, progress_bar.grid_remove)
                
        def on_keys_generated(public_path: Path, private_path: Path) -> None:
            public_key_var.set(str(public_path))
            private_key_var.set(str(private_path))
            sender_public_entry_var.set(str(public_path))
            receiver_private_entry_var.set(str(private_path))
            progress_bar.stop()
            progress_bar.grid_remove()
            set_status(f"Da tao khoa cho ben nhan tai {public_path.name} va {private_path.name}.")
            messagebox.showinfo("Tao khoa", "Da tao khoa cho ben nhan thanh cong.")
            
        set_status("Đang xử lý sinh khóa... Vui lòng đợi.")
        progress_bar.grid()
        progress_bar.start(15)
        import threading
        threading.Thread(target=task, daemon=True).start()

    def encrypt_for_receiver() -> None:
        def task():
            try:
                public_key_path = resolve_path(sender_public_entry_var.get().strip(), base_dir)
                output_path = resolve_path(sender_cipher_entry_var.get().strip() or "cipher.json", base_dir)
                public_key = load_public_key(public_key_path)
                
                if sender_mode_var.get() == 1:
                    message = sender_input.get("1.0", "end-1c")
                    ciphertext = encrypt_alpha_message(message, public_key)
                    normalized = normalize_alpha_message(message)
                else:
                    file_path = resolve_path(sender_file_entry_var.get().strip(), base_dir)
                    file_bytes = file_path.read_bytes()
                    ciphertext = encrypt_file_hybrid(file_bytes, public_key, original_filename=file_path.name)
                    normalized = f"[File {file_path.name}]"
                    
                dump_json(output_path, ciphertext)
                root.after(0, lambda n=normalized, o=output_path: on_encrypted(n, o))
            except Exception as exc:
                root.after(0, lambda e=exc: messagebox.showerror("Loi ma hoa", str(e)))
                root.after(0, lambda: set_status("Lỗi khi mã hóa."))
                root.after(0, progress_bar.stop)
                root.after(0, progress_bar.grid_remove)
                
        def on_encrypted(normalized, output_path):
            normalized_var.set(normalized)
            receiver_cipher_entry_var.set(str(output_path))
            receiver_output.configure(state="normal")
            receiver_output.delete("1.0", "end")
            receiver_output.insert("1.0", "Ban ma da duoc tao. Ben nhan co the mo file nay de giai ma.")
            receiver_output.configure(state="disabled")
            progress_bar.stop()
            progress_bar.grid_remove()
            set_status(f"Ben gui da ma hoa va luu ban ma tai {output_path.name}.")
            messagebox.showinfo("Ma hoa", f"Da ma hoa thong diep.\nDang chuan hoa: {normalized}")
            
        set_status("Đang mã hóa thông điệp...")
        progress_bar.grid()
        progress_bar.start(15)
        import threading
        threading.Thread(target=task, daemon=True).start()

    def decrypt_for_receiver() -> None:
        def task():
            try:
                private_key_path = resolve_path(receiver_private_entry_var.get().strip(), base_dir)
                cipher_path = resolve_path(receiver_cipher_entry_var.get().strip(), base_dir)
                private_key = load_private_key(private_key_path)
                ciphertext = load_json(cipher_path)
                
                if ciphertext.get("encoding") == "alphabet-base26":
                    plaintext = decrypt_alpha_message(ciphertext, private_key)
                    is_file = False
                elif ciphertext.get("encoding") == "hybrid-hex":
                    plaintext = decrypt_file_hybrid(ciphertext, private_key)
                    is_file = True
                else:
                    plaintext = decrypt_bytes(ciphertext, private_key)
                    is_file = True
                
                root.after(0, lambda p=plaintext, c=cipher_path, f=is_file: on_decrypted(p, c, f))
            except Exception as exc:
                root.after(0, lambda e=exc: messagebox.showerror("Loi giai ma", str(e)))
                root.after(0, lambda: set_status("Lỗi khi giải mã."))
                root.after(0, progress_bar.stop)
                root.after(0, progress_bar.grid_remove)
                
        def on_decrypted(plaintext, cipher_path, is_file):
            if is_file:
                save_path = filedialog.asksaveasfilename(
                    title="Luu file giai ma",
                    initialdir=str(base_dir),
                    defaultextension=".*",
                    filetypes=[("All files", "*.*")]
                )
                if save_path:
                    Path(save_path).write_bytes(plaintext)
                    msg = f"Đã lưu file giải mã tại: {save_path}"
                else:
                    msg = "Đã hủy lưu file."
                receiver_output.configure(state="normal")
                receiver_output.delete("1.0", "end")
                receiver_output.insert("1.0", msg)
                receiver_output.configure(state="disabled")
            else:
                receiver_output.configure(state="normal")
                receiver_output.delete("1.0", "end")
                receiver_output.insert("1.0", plaintext)
                receiver_output.configure(state="disabled")
            progress_bar.stop()
            progress_bar.grid_remove()
            set_status(f"Ben nhan da giai ma thanh cong tu {cipher_path.name}.")
            
        set_status("Đang giải mã thông điệp...")
        progress_bar.grid()
        progress_bar.start(15)
        import threading
        threading.Thread(target=task, daemon=True).start()

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
    signature_tab = ttk.Frame(notebook, style="App.TFrame", padding=18)
    help_tab = ttk.Frame(notebook, style="App.TFrame", padding=18)
    notebook.add(receiver_tab, text="Ben Nhan")
    notebook.add(sender_tab, text="Ben Gui")
    notebook.add(signature_tab, text="Chu Ky So")
    notebook.add(help_tab, text="Huong Dan")

    key_card = ttk.LabelFrame(receiver_tab, text="1. Tao khoa cho ben nhan", style="Card.TLabelframe", padding=16)
    key_card.pack(fill="x", pady=(0, 14))
    
    ttk.Label(key_card, text="Che do sinh Prime:", background="#ffffff").grid(row=0, column=0, sticky="w", pady=(0, 10))
    mode_frame = ttk.Frame(key_card, style="Card.TLabelframe")
    mode_frame.grid(row=0, column=1, columnspan=2, sticky="w", pady=(0, 10))
    ttk.Radiobutton(mode_frame, text="1. Nhanh (Xac suat)", variable=prime_mode_var, value=1).pack(side="left", padx=(0, 10))
    ttk.Radiobutton(mode_frame, text="2. An toan (Tu Pool)", variable=prime_mode_var, value=2).pack(side="left", padx=(0, 10))
    ttk.Radiobutton(mode_frame, text="3. Tuy chinh (Co chung chi)", variable=prime_mode_var, value=3).pack(side="left")
    
    ttk.Label(key_card, text="Tien to ten khoa:").grid(row=1, column=0, sticky="w")
    ttk.Entry(key_card, textvariable=key_prefix_var, width=42).grid(row=1, column=1, sticky="ew", padx=(10, 10))
    ttk.Button(key_card, text="Tao khoa", style="Action.TButton", command=generate_receiver_keys).grid(row=1, column=2, sticky="ew")
    ttk.Label(key_card, text="Khoa cong khai:").grid(row=2, column=0, sticky="w", pady=(12, 0))
    ttk.Entry(key_card, textvariable=public_key_var).grid(row=2, column=1, columnspan=2, sticky="ew", padx=(10, 0), pady=(12, 0))
    ttk.Label(key_card, text="Khoa bi mat:").grid(row=3, column=0, sticky="w", pady=(10, 0))
    ttk.Entry(key_card, textvariable=private_key_var).grid(row=3, column=1, columnspan=2, sticky="ew", padx=(10, 0), pady=(10, 0))
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

    ttk.Label(sender_card, text="Che do ma hoa:", background="#ffffff").grid(row=1, column=0, sticky="w", pady=(10, 5))
    s_mode_frame = ttk.Frame(sender_card, style="Card.TLabelframe")
    s_mode_frame.grid(row=1, column=1, columnspan=2, sticky="w", pady=(10, 5))
    ttk.Radiobutton(s_mode_frame, text="1. Van ban (A-Z)", variable=sender_mode_var, value=1, command=lambda: toggle_sender_mode()).pack(side="left", padx=(0, 10))
    ttk.Radiobutton(s_mode_frame, text="2. File (Anh, PDF...)", variable=sender_mode_var, value=2, command=lambda: toggle_sender_mode()).pack(side="left")

    input_container = ttk.Frame(sender_card, style="Card.TLabelframe")
    input_container.grid(row=2, column=0, columnspan=3, sticky="nsew", pady=(5, 10))
    input_container.columnconfigure(1, weight=1)
    
    text_frame = ttk.Frame(input_container, style="Card.TLabelframe")
    text_frame.columnconfigure(1, weight=1)
    text_frame.rowconfigure(0, weight=1)
    ttk.Label(text_frame, text="Thong diep goc:").grid(row=0, column=0, sticky="nw", pady=(0, 0))
    sender_input = scrolledtext.ScrolledText(text_frame, height=8, wrap="word", font=("Consolas", 11), bg="#f9fafb", relief="flat")
    sender_input.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
    sender_input.bind("<KeyRelease>", refresh_normalized_preview)
    ttk.Label(text_frame, text="Sau chuan hoa A-Z:").grid(row=1, column=0, sticky="w", pady=(10, 0))
    ttk.Entry(text_frame, textvariable=normalized_var, state="readonly").grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(10, 0))
    
    file_frame = ttk.Frame(input_container, style="Card.TLabelframe")
    file_frame.columnconfigure(1, weight=1)
    ttk.Label(file_frame, text="Chon file goc:").grid(row=0, column=0, sticky="w")
    ttk.Entry(file_frame, textvariable=sender_file_entry_var).grid(row=0, column=1, sticky="ew", padx=(10, 10))
    ttk.Button(file_frame, text="Chon File...", command=lambda: choose_open_file(sender_file_entry_var, [("All files", "*.*")])).grid(row=0, column=2, sticky="ew")

    def toggle_sender_mode():
        if sender_mode_var.get() == 1:
            file_frame.grid_remove()
            text_frame.grid(row=0, column=0, sticky="nsew")
        else:
            text_frame.grid_remove()
            file_frame.grid(row=0, column=0, sticky="nsew")
            
    toggle_sender_mode()

    ttk.Label(sender_card, text="File ban ma dau ra:").grid(row=3, column=0, sticky="w", pady=(10, 0))
    ttk.Entry(sender_card, textvariable=sender_cipher_entry_var).grid(row=3, column=1, sticky="ew", padx=(10, 10), pady=(10, 0))
    ttk.Button(
        sender_card,
        text="Luu tai",
        command=lambda: choose_save_file(sender_cipher_entry_var, ".json", [("JSON", "*.json"), ("All files", "*.*")]),
    ).grid(row=3, column=2, sticky="ew", pady=(10, 0))
    ttk.Button(sender_card, text="Ma hoa", style="Action.TButton", command=encrypt_for_receiver).grid(
        row=4, column=0, columnspan=3, sticky="ew", pady=(16, 0)
    )
    sender_card.columnconfigure(1, weight=1)
    sender_card.rowconfigure(2, weight=1)

    # === THÊM TAB CHỮ KÝ SỐ ===
    sig_key_var = tk.StringVar(value=str(base_dir / "sender_key.private.json"))
    sig_file_var = tk.StringVar()
    sig_out_var = tk.StringVar(value=str(base_dir / "signature.json"))
    ver_key_var = tk.StringVar(value=str(base_dir / "sender_key.public.json"))
    ver_file_var = tk.StringVar()
    ver_sig_var = tk.StringVar(value=str(base_dir / "signature.json"))
    
    def sign_action():
        def task():
            try:
                private_key = load_private_key(resolve_path(sig_key_var.get(), base_dir))
                msg_text = sig_msg_input.get("1.0", "end-1c")
                if sig_mode_var.get() == 1:
                    payload = msg_text.encode("utf-8")
                else:
                    payload = resolve_path(sig_file_var.get(), base_dir).read_bytes()
                signature = sign_bytes(payload, private_key)
                out_path = resolve_path(sig_out_var.get() or "signature.json", base_dir)
                dump_json(out_path, signature)
                root.after(0, lambda: messagebox.showinfo("Thành công", f"Đã ký và lưu chữ ký vào {out_path.name}"))
            except Exception as e:
                root.after(0, lambda e=e: messagebox.showerror("Lỗi", str(e)))
        import threading
        threading.Thread(target=task, daemon=True).start()

    def verify_action():
        def task():
            try:
                public_key = load_public_key(resolve_path(ver_key_var.get(), base_dir))
                signature = load_json(resolve_path(ver_sig_var.get(), base_dir))
                msg_text = ver_msg_input.get("1.0", "end-1c")
                if ver_mode_var.get() == 1:
                    payload = msg_text.encode("utf-8")
                else:
                    payload = resolve_path(ver_file_var.get(), base_dir).read_bytes()
                is_valid = verify_signature(payload, signature, public_key)
                if is_valid:
                    root.after(0, lambda: messagebox.showinfo("Kết quả", "HỢP LỆ: Chữ ký đúng! File nguyên vẹn."))
                else:
                    root.after(0, lambda: messagebox.showerror("Kết quả", "KHÔNG HỢP LỆ: Chữ ký sai! File bị sửa hoặc sai người gửi."))
            except Exception as e:
                root.after(0, lambda e=e: messagebox.showerror("Lỗi", str(e)))
        import threading
        threading.Thread(target=task, daemon=True).start()

    sig_card = ttk.LabelFrame(signature_tab, text="1. Ký Số (Bên Gửi ký bằng Private Key)", style="Card.TLabelframe", padding=16)
    sig_card.pack(fill="x", pady=(0, 10))
    ttk.Label(sig_card, text="Private Key:").grid(row=0, column=0, sticky="w")
    ttk.Entry(sig_card, textvariable=sig_key_var).grid(row=0, column=1, sticky="ew", padx=10)
    ttk.Button(sig_card, text="Mở...", command=lambda: choose_open_file(sig_key_var, [("JSON", "*.json")])).grid(row=0, column=2)
    sig_mode_var = tk.IntVar(value=1)
    ttk.Radiobutton(sig_card, text="Ký Văn bản", variable=sig_mode_var, value=1).grid(row=1, column=0, sticky="w", pady=5)
    ttk.Radiobutton(sig_card, text="Ký File", variable=sig_mode_var, value=2).grid(row=1, column=1, sticky="w", pady=5)
    sig_msg_input = scrolledtext.ScrolledText(sig_card, height=4)
    sig_msg_input.grid(row=2, column=0, columnspan=3, sticky="ew", pady=5)
    ttk.Entry(sig_card, textvariable=sig_file_var).grid(row=3, column=0, columnspan=2, sticky="ew", padx=(0,10))
    ttk.Button(sig_card, text="Chọn File...", command=lambda: choose_open_file(sig_file_var, [("All files", "*.*")])).grid(row=3, column=2)
    ttk.Label(sig_card, text="Lưu Chữ ký (.json):").grid(row=4, column=0, sticky="w", pady=5)
    ttk.Entry(sig_card, textvariable=sig_out_var).grid(row=4, column=1, sticky="ew", padx=10, pady=5)
    ttk.Button(sig_card, text="Tạo Chữ Ký", style="Action.TButton", command=sign_action).grid(row=4, column=2, pady=5)
    sig_card.columnconfigure(1, weight=1)

    ver_card = ttk.LabelFrame(signature_tab, text="2. Kiểm tra (Bên Nhận dùng Public Key của người gửi)", style="Card.TLabelframe", padding=16)
    ver_card.pack(fill="x", pady=0)
    ttk.Label(ver_card, text="Public Key:").grid(row=0, column=0, sticky="w")
    ttk.Entry(ver_card, textvariable=ver_key_var).grid(row=0, column=1, sticky="ew", padx=10)
    ttk.Button(ver_card, text="Mở...", command=lambda: choose_open_file(ver_key_var, [("JSON", "*.json")])).grid(row=0, column=2)
    ver_mode_var = tk.IntVar(value=1)
    ttk.Radiobutton(ver_card, text="Văn bản", variable=ver_mode_var, value=1).grid(row=1, column=0, sticky="w", pady=5)
    ttk.Radiobutton(ver_card, text="File", variable=ver_mode_var, value=2).grid(row=1, column=1, sticky="w", pady=5)
    ver_msg_input = scrolledtext.ScrolledText(ver_card, height=4)
    ver_msg_input.grid(row=2, column=0, columnspan=3, sticky="ew", pady=5)
    ttk.Entry(ver_card, textvariable=ver_file_var).grid(row=3, column=0, columnspan=2, sticky="ew", padx=(0,10))
    ttk.Button(ver_card, text="Chọn File...", command=lambda: choose_open_file(ver_file_var, [("All files", "*.*")])).grid(row=3, column=2)
    ttk.Label(ver_card, text="File Chữ ký (.json):").grid(row=4, column=0, sticky="w", pady=5)
    ttk.Entry(ver_card, textvariable=ver_sig_var).grid(row=4, column=1, sticky="ew", padx=10, pady=5)
    ttk.Button(ver_card, text="Mở...", command=lambda: choose_open_file(ver_sig_var, [("JSON", "*.json")])).grid(row=4, column=2, pady=5)
    ttk.Button(ver_card, text="Kiểm tra", style="Action.TButton", command=verify_action).grid(row=5, column=0, columnspan=3, pady=5)
    ver_card.columnconfigure(1, weight=1)

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

    status_frame = ttk.Frame(root, style="App.TFrame")
    status_frame.pack(fill="x", side="bottom", padx=20, pady=(0, 16))
    status_frame.columnconfigure(0, weight=1)
    
    status_bar = ttk.Label(status_frame, textvariable=status_var, anchor="w", style="Hint.TLabel")
    status_bar.grid(row=0, column=0, sticky="ew")
    
    progress_bar = ttk.Progressbar(status_frame, mode="indeterminate", length=180)
    progress_bar.grid(row=0, column=1, padx=(10, 0))
    progress_bar.grid_remove()

    root.mainloop()


def handle_gui(_args: argparse.Namespace) -> None:
    launch_gui()


def handle_web(args: argparse.Namespace) -> None:
    from web_app import run_server

    browser_host = "127.0.0.1" if args.host == "0.0.0.0" else args.host
    url = f"http://{browser_host}:{args.port}"
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
    genkey.add_argument(
        "--prime-mode",
        type=int,
        choices=[1, 2, 3],
        default=2,
        help="Che do sinh prime (1: Miller-Rabin, 2: Pool, 3: Provable).",
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
            mode = input("Nhap che do (1: Nhanh, 2: Pool an toan, 3: Tu sinh cham) [2]: ").strip() or "2"
            handle_genkey(argparse.Namespace(output=prefix, prime_mode=int(mode)))
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
