#!/usr/bin/env python3
"""
StegoCrypt Web Application
Provides a localhost web GUI for AES-256-GCM image steganography.
"""

import base64
import io
import os
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
import numpy as np
from PIL import Image, ImageDraw

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Ensure stdout handles UTF-8 on Windows console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB max upload

# ----------------- Cryptographic Constants -----------------
MAGIC_HEADER = b"STGC"
HEADER_SIZE = 8          # 4 bytes magic + 4 bytes uint32 length
SALT_SIZE = 16           # 128-bit salt for PBKDF2
NONCE_SIZE = 12          # 96-bit nonce for AES-GCM
TAG_SIZE = 16            # 128-bit authentication tag
KEY_SIZE = 32            # 256-bit AES key
KDF_ITERATIONS = 600_000 # OWASP standard baseline


# ----------------- Crypto Core -----------------

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_payload(plaintext: bytes, password: str) -> bytes:
    """
    Encrypts plaintext with AES-256-GCM.
    Returns: salt (16B) + nonce (12B) + ciphertext_with_tag (len(plaintext) + 16B)
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext_tag = aesgcm.encrypt(nonce, plaintext, associated_data=MAGIC_HEADER)
    return salt + nonce + ciphertext_tag


def decrypt_payload(encrypted_blob: bytes, password: str) -> bytes:
    """
    Decrypts and verifies AES-256-GCM ciphertext.
    Raises InvalidTag if password is wrong or ciphertext has been altered.
    """
    min_len = SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if len(encrypted_blob) < min_len:
        raise ValueError("Payload is smaller than minimum encrypted size.")

    salt = encrypted_blob[:SALT_SIZE]
    nonce = encrypted_blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext_tag = encrypted_blob[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext_tag, associated_data=MAGIC_HEADER)


# ----------------- Steganography Core (LSB) -----------------

def get_image_info_from_pil(img: Image.Image) -> dict:
    w, h = img.size
    total_bits = w * h * 3
    total_bytes = total_bits // 8
    capacity = max(0, total_bytes - HEADER_SIZE)

    has_stego = False
    detected_len = 0
    try:
        arr = np.array(img.convert("RGB"), dtype=np.uint8).reshape(-1)
        if len(arr) >= HEADER_SIZE * 8:
            h_bits = arr[:HEADER_SIZE * 8] & 1
            h_bytes = np.packbits(h_bits).tobytes()
            if h_bytes[:4] == MAGIC_HEADER:
                has_stego = True
                detected_len = int.from_bytes(h_bytes[4:8], "big")
    except Exception:
        pass

    return {
        "width": w,
        "height": h,
        "capacity_bytes": capacity,
        "has_stego": has_stego,
        "detected_length": detected_len,
    }


def embed_data_in_pil_image(img: Image.Image, payload: bytes) -> Image.Image:
    payload_len = len(payload)
    wire_data = MAGIC_HEADER + payload_len.to_bytes(4, byteorder="big") + payload

    rgb_img = img.convert("RGB")
    arr = np.array(rgb_img, dtype=np.uint8)
    flat = arr.reshape(-1)

    bits = np.unpackbits(np.frombuffer(wire_data, dtype=np.uint8))
    needed_bits = len(bits)

    if needed_bits > len(flat):
        max_bytes = (len(flat) // 8) - HEADER_SIZE
        raise ValueError(
            f"Image capacity exceeded. Payload needs {payload_len} bytes, "
            f"but image can store at most {max_bytes} bytes."
        )

    flat[:needed_bits] = (flat[:needed_bits] & 0xFE) | bits
    stego_arr = flat.reshape(arr.shape)
    return Image.fromarray(stego_arr, mode="RGB")


def extract_data_from_pil_image(img: Image.Image) -> bytes:
    rgb_img = img.convert("RGB")
    arr = np.array(rgb_img, dtype=np.uint8)
    flat = arr.reshape(-1)

    if len(flat) < HEADER_SIZE * 8:
        raise ValueError("Image has fewer pixels than required for StegoCrypt header.")

    header_bits = flat[:HEADER_SIZE * 8] & 1
    header_bytes = np.packbits(header_bits).tobytes()

    if header_bytes[:4] != MAGIC_HEADER:
        raise ValueError(
            "No StegoCrypt signature found. This image contains no hidden data, "
            "or it was saved with lossy compression (like JPEG) which destroys LSB bits."
        )

    payload_len = int.from_bytes(header_bytes[4:8], byteorder="big")
    total_bits = (HEADER_SIZE + payload_len) * 8

    if total_bits > len(flat):
        raise ValueError("Corrupted header: encoded length exceeds image capacity.")

    payload_bits = flat[HEADER_SIZE * 8:total_bits] & 1
    return np.packbits(payload_bits).tobytes()


# ----------------- Procedural Cover Generator -----------------

def generate_cover_art(style: str = "cyber", width: int = 800, height: int = 600) -> Image.Image:
    x = np.linspace(0, 1, width)
    y = np.linspace(0, 1, height)
    xx, yy = np.meshgrid(x, y)

    if style == "cosmic":
        # Dark purple & starry nebula pattern
        r = (np.sin(xx * 5) * 60 + 30).clip(0, 255).astype(np.uint8)
        g = (np.cos(yy * 4) * 40 + 20).clip(0, 255).astype(np.uint8)
        b = (np.sin((xx + yy) * 3) * 100 + 120).clip(0, 255).astype(np.uint8)
    elif style == "emerald":
        # Matrix/emerald cyber aesthetic
        r = (np.sin(yy * 6) * 30 + 15).clip(0, 255).astype(np.uint8)
        g = (np.sin(xx * 4 + yy * 4) * 110 + 130).clip(0, 255).astype(np.uint8)
        b = (np.cos(xx * 6) * 50 + 40).clip(0, 255).astype(np.uint8)
    else:  # "cyber" default
        r = (np.sin(xx * 3.1415) * 200 + 40).clip(0, 255).astype(np.uint8)
        g = (np.cos(yy * 3.1415) * 180 + 40).clip(0, 255).astype(np.uint8)
        b = ((xx + yy) / 2 * 230 + 25).clip(0, 255).astype(np.uint8)

    rgb = np.stack([r, g, b], axis=-1)
    img = Image.fromarray(rgb, mode="RGB")
    draw = ImageDraw.Draw(img)

    # Clean border and technical grid overlay
    draw.rectangle([30, 30, width - 30, height - 30], outline=(255, 255, 255, 120), width=2)
    draw.text((45, 45), f"StegoCrypt Canvas // {style.upper()} // {width}x{height}", fill=(255, 255, 255))

    return img


# ----------------- Web Routes -----------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/info", methods=["POST"])
def api_info():
    if "image" not in request.files:
        return jsonify({"error": "No image uploaded"}), 400

    file = request.files["image"]
    try:
        img = Image.open(file.stream)
        info = get_image_info_from_pil(img)
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": f"Failed to analyze image: {str(e)}"}), 400


@app.route("/api/generate-cover", methods=["GET"])
def api_generate_cover():
    style = request.args.get("style", "cyber")
    width = int(request.args.get("width", 800))
    height = int(request.args.get("height", 600))

    img = generate_cover_art(style=style, width=width, height=height)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png", as_attachment=True, download_name=f"cover_{style}.png")


@app.route("/api/hide", methods=["POST"])
def api_hide():
    if "cover" not in request.files:
        return jsonify({"error": "Missing cover image file."}), 400

    cover_file = request.files["cover"]
    password = request.form.get("password", "").strip()
    secret_type = request.form.get("secret_type", "text")

    if not password:
        return jsonify({"error": "Password cannot be empty."}), 400

    # Prepare plaintext payload with format metadata byte
    if secret_type == "file":
        if "secret_file" not in request.files:
            return jsonify({"error": "Missing secret file."}), 400
        sec_file = request.files["secret_file"]
        filename = os.path.basename(sec_file.filename or "secret_attachment")
        raw_file_bytes = sec_file.read()
        name_bytes = filename.encode("utf-8")[:255]
        # Format: \x01 + 1 byte name length + filename bytes + raw file bytes
        plaintext = b"\x01" + bytes([len(name_bytes)]) + name_bytes + raw_file_bytes
    else:
        secret_text = request.form.get("secret_text", "")
        if not secret_text:
            return jsonify({"error": "Secret text cannot be empty."}), 400
        # Format: \x00 + UTF-8 text bytes
        plaintext = b"\x00" + secret_text.encode("utf-8")

    try:
        cover_img = Image.open(cover_file.stream)
        encrypted_blob = encrypt_payload(plaintext, password)
        stego_img = embed_data_in_pil_image(cover_img, encrypted_blob)

        buf = io.BytesIO()
        stego_img.save(buf, format="PNG")
        buf.seek(0)

        # Also provide base64 for live frontend preview
        b64_preview = base64.b64encode(buf.getvalue()).decode("ascii")

        return jsonify({
            "success": True,
            "embedded_bytes": len(encrypted_blob),
            "image_data_url": f"data:image/png;base64,{b64_preview}"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/reveal", methods=["POST"])
def api_reveal():
    if "stego" not in request.files:
        return jsonify({"error": "Missing stego image file."}), 400

    stego_file = request.files["stego"]
    password = request.form.get("password", "").strip()

    if not password:
        return jsonify({"error": "Password cannot be empty."}), 400

    try:
        stego_img = Image.open(stego_file.stream)
        encrypted_blob = extract_data_from_pil_image(stego_img)
    except Exception as e:
        return jsonify({"error": f"Extraction error: {str(e)}"}), 400

    try:
        decrypted = decrypt_payload(encrypted_blob, password)
    except InvalidTag:
        return jsonify({
            "error": "Authentication Failed! Either the password is incorrect or the image pixels were altered/compressed."
        }), 400
    except Exception as e:
        return jsonify({"error": f"Decryption error: {str(e)}"}), 400

    # Inspect payload type indicator
    if len(decrypted) > 0 and decrypted[0] == 0x01:
        # File payload
        name_len = decrypted[1]
        filename = decrypted[2:2 + name_len].decode("utf-8", errors="replace")
        file_bytes = decrypted[2 + name_len:]
        b64_file = base64.b64encode(file_bytes).decode("ascii")
        return jsonify({
            "success": True,
            "type": "file",
            "filename": filename,
            "size": len(file_bytes),
            "data_b64": b64_file
        })
    elif len(decrypted) > 0 and decrypted[0] == 0x00:
        # Text payload with format tag
        text = decrypted[1:].decode("utf-8", errors="replace")
        return jsonify({
            "success": True,
            "type": "text",
            "content": text
        })
    else:
        # Legacy CLI payload without type flag
        try:
            text = decrypted.decode("utf-8")
            return jsonify({
                "success": True,
                "type": "text",
                "content": text
            })
        except UnicodeDecodeError:
            b64_file = base64.b64encode(decrypted).decode("ascii")
            return jsonify({
                "success": True,
                "type": "file",
                "filename": "extracted_secret.bin",
                "size": len(decrypted),
                "data_b64": b64_file
            })


@app.route("/api/tamper", methods=["POST"])
def api_tamper():
    """Modifies pixel data inside the ciphertext section to demonstrate AEAD tamper-resistance."""
    if "stego" not in request.files:
        return jsonify({"error": "Missing stego image file."}), 400

    file = request.files["stego"]
    try:
        img = Image.open(file.stream).convert("RGB")
        modified = img.copy()
        draw = ImageDraw.Draw(modified)
        # Modify pixels 30-45 in row 0 (inside AES-GCM ciphertext)
        draw.line([(30, 0), (45, 0)], fill=(255, 0, 0), width=1)

        buf = io.BytesIO()
        modified.save(buf, format="PNG")
        buf.seek(0)
        b64 = base64.b64encode(buf.getvalue()).decode("ascii")

        return jsonify({
            "success": True,
            "image_data_url": f"data:image/png;base64,{b64}"
        })
    except Exception as e:
        return jsonify({"error": f"Tampering failed: {str(e)}"}), 400


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n=======================================================")
    print(f"🔒 StegoCrypt Web Server running at:")
    print(f"👉 http://localhost:{port}")
    print(f"👉 http://127.0.0.1:{port}")
    print(f"=======================================================\n")
    app.run(host="0.0.0.0", port=port, debug=False)
