#!/usr/bin/env python3
"""
StegoCrypt: Authenticated Cryptographic Steganography Tool
Hides AES-256-GCM encrypted data inside the Least Significant Bits (LSB) of PNG images.
"""

import argparse
import getpass
import os
import sys
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Ensure stdout handles UTF-8 on Windows consoles without charmap crash
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

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
    Raises InvalidTag if password is incorrect or data was modified.
    """
    min_len = SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if len(encrypted_blob) < min_len:
        raise ValueError("Payload is smaller than minimum encrypted size.")

    salt = encrypted_blob[:SALT_SIZE]
    nonce = encrypted_blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext_tag = encrypted_blob[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    # Decrypt and authenticate against associated_data
    return aesgcm.decrypt(nonce, ciphertext_tag, associated_data=MAGIC_HEADER)


# ----------------- Steganography Core (LSB) -----------------

def get_image_capacity(image_path: str) -> int:
    """Returns max embeddable payload size in bytes."""
    with Image.open(image_path) as img:
        width, height = img.size
        # RGB has 3 channels = 3 bits per pixel
        total_bits = width * height * 3
        total_bytes = total_bits // 8
        return max(0, total_bytes - HEADER_SIZE)


def embed_data_in_image(cover_path: str, payload: bytes, output_path: str):
    """Embeds payload into the LSBs of cover PNG."""
    payload_len = len(payload)
    wire_data = MAGIC_HEADER + payload_len.to_bytes(4, byteorder="big") + payload

    with Image.open(cover_path) as img:
        rgb_img = img.convert("RGB")
        arr = np.array(rgb_img, dtype=np.uint8)

    flat = arr.reshape(-1)
    bits = np.unpackbits(np.frombuffer(wire_data, dtype=np.uint8))
    needed_bits = len(bits)

    if needed_bits > len(flat):
        max_bytes = (len(flat) // 8) - HEADER_SIZE
        raise ValueError(
            f"Image capacity exceeded! Payload needs {payload_len} bytes, "
            f"but this image can only store up to {max_bytes} bytes."
        )

    # Embed bits into least significant bit
    flat[:needed_bits] = (flat[:needed_bits] & 0xFE) | bits

    stego_arr = flat.reshape(arr.shape)
    stego_img = Image.fromarray(stego_arr, mode="RGB")
    stego_img.save(output_path, format="PNG")


def extract_data_from_image(stego_path: str) -> bytes:
    """Extracts raw embedded payload from the LSBs of a PNG."""
    with Image.open(stego_path) as img:
        rgb_img = img.convert("RGB")
        arr = np.array(rgb_img, dtype=np.uint8)

    flat = arr.reshape(-1)
    if len(flat) < HEADER_SIZE * 8:
        raise ValueError("Image has fewer pixels than required for header.")

    # Read the 64-bit header (Magic + Length)
    header_bits = flat[:HEADER_SIZE * 8] & 1
    header_bytes = np.packbits(header_bits).tobytes()

    magic = header_bytes[:4]
    if magic != MAGIC_HEADER:
        raise ValueError(
            "No StegoCrypt signature found. This image does not contain hidden data, "
            "or it was compressed/modified by an external app (e.g. JPEG lossy compression)."
        )

    payload_len = int.from_bytes(header_bytes[4:8], byteorder="big")
    total_bits = (HEADER_SIZE + payload_len) * 8

    if total_bits > len(flat):
        raise ValueError("Corrupted header: encoded length exceeds image dimensions.")

    payload_bits = flat[HEADER_SIZE * 8:total_bits] & 1
    return np.packbits(payload_bits).tobytes()


# ----------------- Utility Helpers -----------------

def create_sample_cover(output_path: str, width: int = 800, height: int = 600):
    """Generates a sample colorful gradient PNG image to use as cover."""
    # Create smooth color gradient
    x = np.linspace(0, 1, width)
    y = np.linspace(0, 1, height)
    xx, yy = np.meshgrid(x, y)

    r = (np.sin(xx * 3.1415) * 255).astype(np.uint8)
    g = (np.cos(yy * 3.1415) * 255).astype(np.uint8)
    b = ((xx + yy) / 2 * 255).astype(np.uint8)

    rgb = np.stack([r, g, b], axis=-1)
    img = Image.fromarray(rgb, mode="RGB")

    draw = ImageDraw.Draw(img)
    # Add some graphic shapes
    draw.rectangle([60, 60, width - 60, height - 60], outline=(255, 255, 255), width=3)
    draw.text((80, 80), "StegoCrypt Cover Canvas", fill=(255, 255, 255))

    img.save(output_path, format="PNG")


# ----------------- CLI Commands -----------------

def cmd_create_cover(args):
    create_sample_cover(args.output, args.width, args.height)
    cap = get_image_capacity(args.output)
    print(f"🎨 Generated sample cover image: {args.output}")
    print(f"📐 Dimensions: {args.width}x{args.height} px")
    print(f"📦 Maximum secret payload capacity: {cap:,} bytes (~{cap / 1024:.1f} KB)")


def cmd_info(args):
    if not os.path.exists(args.image):
        print(f"❌ File not found: {args.image}")
        sys.exit(1)

    with Image.open(args.image) as img:
        w, h = img.size
        fmt = img.format

    cap = get_image_capacity(args.image)
    print(f"🖼️  Image: {args.image}")
    print(f"   Format: {fmt} | Resolution: {w}x{h} px")
    print(f"   Max Secret Capacity: {cap:,} bytes (~{cap / 1024:.1f} KB)")

    # Check for StegoCrypt signature
    try:
        with Image.open(args.image) as img:
            arr = np.array(img.convert("RGB"), dtype=np.uint8).reshape(-1)
            h_bits = arr[:HEADER_SIZE * 8] & 1
            h_bytes = np.packbits(h_bits).tobytes()
            if h_bytes[:4] == MAGIC_HEADER:
                p_len = int.from_bytes(h_bytes[4:8], "big")
                print(f"   🔍 StegoCrypt Payload: DETECTED ({p_len:,} encrypted bytes embedded)")
            else:
                print("   🔍 StegoCrypt Payload: None detected (Clean image)")
    except Exception:
        print("   🔍 StegoCrypt Payload: None detected")


def cmd_hide(args):
    if not os.path.exists(args.cover):
        print(f"❌ Cover image not found: {args.cover}")
        sys.exit(1)

    # Determine secret bytes
    if args.file:
        if not os.path.exists(args.secret):
            print(f"❌ Secret file not found: {args.secret}")
            sys.exit(1)
        with open(args.secret, "rb") as f:
            plaintext = f.read()
        print(f"📄 Reading secret file: {args.secret} ({len(plaintext):,} bytes)")
    else:
        plaintext = args.secret.encode("utf-8")

    password = args.password
    if not password:
        password = getpass.getpass("🔑 Enter encryption password: ")
        confirm = getpass.getpass("🔑 Confirm password: ")
        if password != confirm:
            print("❌ Passwords do not match.")
            sys.exit(1)

    print("🔒 Encrypting with AES-256-GCM + PBKDF2 (600,000 iterations)...")
    encrypted_payload = encrypt_payload(plaintext, password)

    print("🖼️  Embedding encrypted payload into image LSBs...")
    try:
        embed_data_in_image(args.cover, encrypted_payload, args.output)
        print(f"✅ Success! Stego image saved to: {args.output}")
        print(f"   Embedded {len(encrypted_payload):,} encrypted bytes.")
    except ValueError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


def cmd_reveal(args):
    if not os.path.exists(args.stego):
        print(f"❌ Stego image not found: {args.stego}")
        sys.exit(1)

    password = args.password
    if not password:
        password = getpass.getpass("🔑 Enter decryption password: ")

    print("🔍 Extracting hidden bits from image...")
    try:
        encrypted_payload = extract_data_from_image(args.stego)
    except ValueError as e:
        print(f"❌ Extraction error: {e}")
        sys.exit(1)

    print(f"🔒 Decrypting {len(encrypted_payload):,} bytes with AES-256-GCM...")
    try:
        decrypted = decrypt_payload(encrypted_payload, password)
    except InvalidTag:
        print("❌ Authentication failed! Either:")
        print("   1) The password is incorrect.")
        print("   2) The image pixels were modified/compressed/tampered with.")
        sys.exit(1)

    if args.output:
        with open(args.output, "wb") as f:
            f.write(decrypted)
        print(f"✅ Decrypted secret saved to: {args.output} ({len(decrypted):,} bytes)")
    else:
        try:
            text = decrypted.decode("utf-8")
            print("\n🔓 Decrypted Secret Message:")
            print("----------------------------------------")
            print(text)
            print("----------------------------------------")
        except UnicodeDecodeError:
            print("⚠️ Secret is binary data. Please re-run with --output <file> to save it.")


def cmd_tamper(args):
    """Demonstrates tamper detection by modifying pixels within the ciphertext payload region."""
    if not os.path.exists(args.image):
        print(f"❌ Image not found: {args.image}")
        sys.exit(1)

    with Image.open(args.image) as img:
        modified = img.copy()
        draw = ImageDraw.Draw(modified)
        # Header is in first 22 pixels (64 bits / 3 channels).
        # Modifying pixels 30 to 40 leaves the header intact but corrupts the encrypted ciphertext.
        draw.line([(30, 0), (40, 0)], fill=(255, 0, 0), width=1)
        modified.save(args.output, format="PNG")

    print(f"⚠️ Created tampered image: {args.output}")
    print("   Altered pixels 30-40 (inside the AES-GCM ciphertext payload, past the header).")


def main():
    parser = argparse.ArgumentParser(
        description="StegoCrypt: AES-256-GCM Authenticated Image Steganography"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # generate-cover
    p_gen = sub.add_parser("create-cover", help="Generate a sample cover PNG image")
    p_gen.add_argument("output", help="Output path (e.g. cover.png)")
    p_gen.add_argument("--width", type=int, default=800, help="Image width (default: 800)")
    p_gen.add_argument("--height", type=int, default=600, help="Image height (default: 600)")

    # info
    p_info = sub.add_parser("info", help="Inspect image capacity and StegoCrypt presence")
    p_info.add_argument("image", help="Path to image")

    # hide
    p_hide = sub.add_parser("hide", help="Encrypt and hide secret in image")
    p_hide.add_argument("--cover", required=True, help="Input cover PNG")
    p_hide.add_argument("--secret", required=True, help="Secret text string OR file path")
    p_hide.add_argument("--file", action="store_true", help="Treat secret as a file path")
    p_hide.add_argument("--output", required=True, help="Output stego PNG path")
    p_hide.add_argument("--password", help="Password (prompted securely if omitted)")

    # reveal
    p_reveal = sub.add_parser("reveal", help="Extract and decrypt secret from stego image")
    p_reveal.add_argument("--stego", required=True, help="Path to stego PNG image")
    p_reveal.add_argument("--output", help="Optional output path for file secrets")
    p_reveal.add_argument("--password", help="Password (prompted securely if omitted)")

    # tamper
    p_tamper = sub.add_parser("tamper", help="Simulate an attacker altering the stego image")
    p_tamper.add_argument("image", help="Input stego PNG")
    p_tamper.add_argument("output", help="Output tampered PNG")

    args = parser.parse_args()

    dispatch = {
        "create-cover": cmd_create_cover,
        "info": cmd_info,
        "hide": cmd_hide,
        "reveal": cmd_reveal,
        "tamper": cmd_tamper,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
