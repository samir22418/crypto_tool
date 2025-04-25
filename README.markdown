# SamirCryptoTool

![SamirCryptoTool Cover](SamirCryptoTool_Cover.jpg)

A Python-based cryptography tool for exploring encryption, hashing, and digital signatures.

---

## Overview

**SamirCryptoTool** is a desktop application built with Python and Tkinter, providing a user-friendly interface to experiment with cryptographic techniques, including:

- **Symmetric Encryption**: AES, DES
- **Asymmetric Encryption**: RSA
- **Classical Ciphers**: Caesar, Vigenere
- **Hashing**: MD5, SHA-1, SHA-256, SHA-512
- **Digital Signatures**: Sign/verify with RSA

---

## Installation

### Requirements
- Python 3.6+
- Libraries: `tkinter`, `pycryptodome`, `cryptography`

### Setup
1. Install dependencies:
   ```bash
   pip install pycryptodome cryptography
   ```
2. Download the project files, including `samir_crypto_tool.py` and `SamirCryptoTool_Cover.jpg`.
3. Run the app:
   ```bash
   python samir_crypto_tool.py
   ```

---

## Usage

1. Launch the app to access five tabs: Symmetric, Asymmetric (RSA), Classical, Hashing, and Digital Signature.
2. Each tab provides:
   - Input field for messages
   - Key generation (where applicable)
   - Action selection (e.g., encrypt, sign)
   - Output display and file save/load options

**Example**: To encrypt with AES:
- Go to the **Symmetric** tab.
- Click "Make New Key".
- Enter a message, select "AES Encrypt", and click "Go!".
- Save the result with "Save Result".

---

## Credits

- **Author**: Samir Walid Samir (ID: 412200040)
- **Built With**: Python 3, Tkinter, `pycryptodome`, `cryptography`

---

## License

MIT License. Free to use, modify, and distribute with attribution.

*Last updated: April 25, 2025*