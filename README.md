# 🖼️ StegoCrypt: Authenticated Image Steganography

**StegoCrypt** combines modern authenticated symmetric cryptography (**AES-256-GCM**) with Least Significant Bit (**LSB**) image steganography. It allows you to conceal sensitive messages or arbitrary files inside normal-looking PNG images, rendering them imperceptible to human observers while guaranteeing confidentiality and tamper-evident cryptographic integrity.

---

## 🔒 Cryptographic & Steganographic Architecture

### 1. Key Derivation: PBKDF2-HMAC-SHA256
- User passwords cannot serve as raw cryptographic keys.
- A **128-bit cryptographically secure random salt** (`os.urandom(16)`) is generated for every encryption.
- The key is derived using **PBKDF2-HMAC-SHA256** with **600,000 iterations** (OWASP recommended baseline) to mitigate rainbow tables and GPU brute-force attacks.

### 2. Authenticated Encryption: AES-256-GCM (AEAD)
- Provides **confidentiality** (encryption) and **authenticity/integrity** (128-bit authentication tag).
- Each encryption utilizes a fresh **96-bit random nonce** (`os.urandom(12)`).
- The magic header `STGC` is bound into the authentication tag as Associated Data (`associated_data=b"STGC"`).
- **Tamper Detection**: If even 1 bit of the image or ciphertext is altered, decryption immediately aborts with an authentication failure (`InvalidTag`), preventing malicious bit-flipping attacks.

### 3. Least Significant Bit (LSB) Embedding
- In 24-bit RGB images, each pixel consists of 3 color channels: $(Red, Green, Blue)$ with values $0..255$.
- Modifying the lowest bit of a channel changes the color value by at most $\pm 1$, which is visually indistinguishable to the human eye.
- **Capacity**: For an image of dimensions $W \times H$:
  $$\text{Capacity (bits)} = W \times H \times 3$$
  $$\text{Capacity (bytes)} = \lfloor(W \times H \times 3) / 8\rfloor - 8 \text{ (header)}$$
  *(For example, an $800 \times 600$ image stores over $175 \text{ KB}$ of encrypted payload!)*

### 4. Wire Format
```
+--------------------+-------------------------+-------------------+--------------------+-----------------------------+
| Magic (4 bytes)    | Payload Length (4 bytes)| Salt (16 bytes)   | Nonce (12 bytes)   | Ciphertext + Tag (N bytes)  |
| b'STGC'            | Big-Endian uint32       | CSPRNG Salt       | CSPRNG Nonce       | AES-256-GCM Payload         |
+--------------------+-------------------------+-------------------+--------------------+-----------------------------+
```

---

## 🚀 Setup & Requirements

- Python 3.9+
- `cryptography`
- `Pillow`
- `numpy`

```bash
pip install cryptography Pillow numpy
```

---

## 🛠️ CLI Commands & Usage

### 1. Generate a Test Cover Image
If you don't have a PNG image at hand, generate a procedural gradient image:
```bash
python stegocrypt.py create-cover cover.png --width 800 --height 600
```

### 2. Inspect an Image (Capacity & Detection)
Check maximum storage capacity and whether a StegoCrypt payload exists:
```bash
python stegocrypt.py info cover.png
```

### 3. Hide a Secret Message in an Image
```bash
python stegocrypt.py hide --cover cover.png --secret "Meet at midnight. Passcode: 77-ALPHA" --output stego.png
```
*(You will be securely prompted for your password)*

### 4. Hide an Entire File (Documents, Keys, Archives)
```bash
python stegocrypt.py hide --cover cover.png --secret confidential.pdf --file --output stego_pdf.png
```

### 5. Reveal & Decrypt Hidden Data
For text messages:
```bash
python stegocrypt.py reveal --stego stego.png
```

For extracted files:
```bash
python stegocrypt.py reveal --stego stego_pdf.png --output restored_confidential.pdf
```

### 6. Test Tamper Detection
Simulate an adversary altering image pixels:
```bash
# Modifies pixel data in the encrypted section
python stegocrypt.py tamper stego.png tampered.png

# Attempt to decrypt with the correct password
python stegocrypt.py reveal --stego tampered.png
```
**Output:**
```
❌ Authentication failed! Either:
   1) The password is incorrect.
   2) The image pixels were modified/compressed/tampered with.
```
*(Even with the correct password, AES-GCM detects that pixels were tampered with!)*

---

## ⚠️ Important Note: PNG vs JPEG
Steganography with LSB **strictly requires lossless image formats like PNG**. Lossy formats such as JPEG perform discrete cosine transform (DCT) compression and chroma subsampling, which discard least significant bit data and destroy the encrypted payload.
