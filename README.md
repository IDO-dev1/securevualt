# 🔐 SecureVault

Modern offline password manager built with Python.

SecureVault stores all credentials locally using strong authenticated encryption with AES-256-GCM and Argon2id key derivation.

Built by Ido.

---

# ✨ Features

- AES-256-GCM authenticated encryption
- Argon2id memory-hard key derivation
- Modern dark UI
- Password generator
- Clipboard copy support
- Search functionality
- Local encrypted vault storage
- TOTP secret support
- Automatic encrypted backups
- Tamper detection
- Atomic encrypted saves

---

# 🛡️ Security Architecture

| Layer | Detail |
|---|---|
| Encryption | AES-256-GCM |
| Authentication | Built-in GCM integrity verification |
| Key derivation | Argon2id · 3 passes · 64 MB memory · 4 threads |
| Salt | 32 random bytes per vault |
| Nonce | 12 random bytes generated on every save |
| Storage | Local `.sv1` encrypted binary file |
| Backup | Auto `.bak` encrypted backup |
| Memory protection | Master key wiped on lock |

---

# 📦 Vault File Format

```text
[3 bytes magic "SV1"]
[1 byte version]
[32 bytes Argon2id salt]
[12 bytes AES-GCM nonce]
[N bytes ciphertext + GCM authentication tag]
```

---

# 🔧 Build Instructions

## Install dependencies

```bash
pip install -r requirements.txt
```

## Build executable

```bash
pyinstaller --onefile --windowed --icon=icon.ico --name SecureVault vault_gui.py
```

Executable output:

```text
dist/SecureVault.exe
```

---

# 🔒 Security Improvements

### Fixed vulnerabilities from the original implementation:

1. `save()` incorrectly wrote derived key bytes instead of the real salt
2. Backup encryption reused sensitive material
3. Argon2id output was incorrectly wrapped with SHA256
4. Missing authentication allowed undetected tampering
5. Non-atomic writes risked vault corruption
6. Sensitive key material now cleared from memory on lock

---

# 🚀 Usage

### First launch
Create a master password (minimum 10 characters).

### Add credentials
Click **"+ Add Entry"**

### Generate secure passwords
Use the ⚡ password generator button.

### Copy credentials
Use the **Copy** button next to fields.

### Change master password
Settings → Change Master Password

---

# ⚠ Disclaimer

SecureVault is provided as-is with no warranty.

Always keep backups of your encrypted vault file.
