# 🔐 StegaCrypt AES

**Secure Image Steganography with AES-256-GCM Encryption**

StegaCrypt AES is a browser-based web application that combines **AES-256-GCM authenticated encryption** with **LSB (Least Significant Bit) image steganography** to securely hide encrypted text messages inside images.

The message is encrypted before being embedded into the image, providing two complementary layers of protection: **cryptography** protects the content, while **steganography** conceals the presence of the encrypted data.

## 🌐 Live Demo

🚀 **[Try StegaCrypt AES Live](https://meli-afkl.github.io/StegaCrypt-AES/)**

No installation or backend is required — the application runs entirely in the browser.

---

## 📸 Demo

### Encrypt & Hide

![StegaCrypt encryption](screenshots/encrypt.png)

### Extract & Decrypt

![StegaCrypt decryption](screenshots/decrypt.png)

---

## ✨ Features

- 🔐 AES-256-GCM authenticated encryption
- 🔑 Password-based key derivation using PBKDF2-SHA256
- 🧂 Cryptographically random 16-byte salt
- 🔄 Cryptographically random 12-byte IV for each encryption
- 🖼️ LSB image steganography using RGB channels
- 📏 32-bit payload length header
- 📥 PNG stego image generation and download
- 🔎 Hidden payload extraction
- 🔓 Password-based message decryption
- 🛡️ Payload structure validation
- 🌐 Runs entirely in the browser
- ⚛️ Built with React and Vite
- 🚀 Automatically deployed with GitHub Actions and GitHub Pages

---

## 🔄 How It Works

StegaCrypt first encrypts the secret message and only then hides the encrypted data inside an image.

### Encryption & Embedding

```text
Secret Message
      │
      ▼
User Password
      │
      ▼
PBKDF2 + SHA-256
100,000 iterations
16-byte random salt
      │
      ▼
256-bit AES Key
      │
      ▼
AES-256-GCM Encryption
12-byte random IV
      │
      ▼
Encrypted Payload
      │
      ▼
32-bit Length Header + Payload
      │
      ▼
RGB LSB Embedding
      │
      ▼
PNG Stego Image
```

The user selects an image, enters a secret message and provides a password.

The password is processed using **PBKDF2 with SHA-256**, a randomly generated 16-byte salt and 100,000 iterations. This process derives the 256-bit key used for AES-GCM encryption.

A new random 12-byte IV is generated for every encryption operation.

The resulting encrypted payload is then embedded into the least significant bits of the image's RGB channels.

### Extraction & Decryption

```text
PNG Stego Image
      │
      ▼
Read 32-bit Length Header
      │
      ▼
Extract LSB Payload
      │
      ▼
Recover Salt + IV + Ciphertext
      │
      ▼
PBKDF2 Key Derivation
      │
      ▼
AES-256-GCM Decryption
      │
      ▼
Original Message
```

During extraction, StegaCrypt first reads the 32-bit header to determine exactly how many payload bits are stored inside the image.

The encrypted payload is reconstructed, the AES key is derived again from the supplied password and stored salt, and AES-GCM attempts to authenticate and decrypt the message.

---

## 🛡️ Security Design

StegaCrypt combines **authenticated encryption**, **password-based key derivation**, and **image steganography**.

### Password-Based Key Derivation

The user's password is **not used directly as the AES key**.

Instead, StegaCrypt derives a **256-bit AES key** using:

- PBKDF2
- SHA-256
- 100,000 iterations
- 16-byte cryptographically random salt

A new random salt is generated for every encryption operation.

This prevents identical passwords from deterministically producing the same derived key across encryption operations.

### AES-256-GCM

The secret message is encrypted using **AES-256-GCM** through the browser's Web Crypto API.

Every encryption operation uses a new **12-byte cryptographically random IV**.

AES-GCM provides:

- **Confidentiality** — the plaintext is protected by encryption.
- **Integrity and authentication** — modified ciphertext or an incorrect password causes decryption to fail.

The salt and IV are stored alongside the ciphertext because they are required for key derivation and decryption. They do not need to remain secret.

### Payload Structure

Before being embedded, the encrypted data is serialized into a payload containing:

```text
version
salt
IV
ciphertext
```

The steganographic data is then structured as:

```text
[ 32-bit payload length ][ encrypted payload ]
```

The 32-bit header allows the decoder to determine exactly how many bits must be extracted from the image.

This replaces delimiter-based detection and avoids searching through the extracted data for a special termination string.

### LSB Image Steganography

The encrypted payload is hidden using **Least Significant Bit (LSB) manipulation**.

Each payload bit is stored in the least significant bit of an RGB channel:

```text
Pixel

Red   → LSB may contain data
Green → LSB may contain data
Blue  → LSB may contain data
Alpha → unchanged
```

Only one bit from each RGB channel is modified, keeping changes to individual pixel values minimal.

The application also checks whether the selected image has enough capacity to contain the complete encrypted payload before embedding it.

### PNG Output

The resulting stego image is exported as **PNG**.

PNG uses lossless compression, preserving the pixel values containing the hidden LSB data.

Lossy image compression, such as JPEG compression, may alter pixel values and destroy the embedded information.

> **Note:** StegaCrypt AES is an educational and portfolio project. It demonstrates cryptographic and steganographic concepts but has not undergone an independent security audit and should not be treated as production security software.

---

## 🧰 Tech Stack

- **React**
- **JavaScript**
- **Vite**
- **HTML5**
- **CSS3**
- **Web Crypto API**
- **Canvas API**
- **TextEncoder / TextDecoder**
- **GitHub Actions**
- **GitHub Pages**

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/MeLi-afkl/StegaCrypt-AES.git
```

Enter the project directory:

```bash
cd StegaCrypt-AES
```

Install the dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

Then open the local address displayed by Vite in your browser.

---

## 🧪 Usage

### Encrypt and Hide a Message

1. Select an image.
2. Enter a password.
3. Enter the secret message.
4. Click **Encrypt & Hide Message**.
5. Download the generated PNG stego image.

### Extract and Decrypt a Message

1. Select a PNG image previously generated by StegaCrypt.
2. Enter the same password used during encryption.
3. Click **Extract & Decrypt**.
4. The hidden payload is extracted and decrypted.
5. The original message is displayed.

---

## 🔬 Technical Details

| Component | Implementation |
|---|---|
| Encryption | AES-256-GCM |
| Key derivation | PBKDF2 |
| PBKDF2 hash | SHA-256 |
| PBKDF2 iterations | 100,000 |
| Salt | Random 16 bytes |
| IV | Random 12 bytes |
| Key size | 256 bits |
| Steganography | LSB |
| Channels used | RGB |
| Alpha channel | Unmodified |
| Payload header | 32-bit length |
| Output format | PNG |
| Cryptography API | Web Crypto API |
| Image processing | Canvas API |
| Frontend | React + Vite |
| Deployment | GitHub Actions + GitHub Pages |

---

## 🔒 Privacy

StegaCrypt performs its cryptographic and image-processing operations **locally in the user's browser**.

The current application does not require a backend server to encrypt, embed, extract, or decrypt messages.

This means the selected image, password and secret message do not need to be sent to an application server as part of the StegaCrypt workflow.

---

## 🎯 Project Purpose

StegaCrypt AES was created as a practical exploration of the relationship between **cryptography, information hiding and modern web technologies**.

The project demonstrates an end-to-end workflow combining:

**password-based key derivation → authenticated encryption → payload serialization → LSB embedding → extraction → authenticated decryption**

It also demonstrates the use of browser-native APIs for cryptographic operations and pixel-level image manipulation without requiring a backend server.

---

## 👩‍💻 Author

Developed by **MeLi-afkl**

---

⭐ If you find this project interesting, feel free to explore the source code, try the live demo and experiment with it.