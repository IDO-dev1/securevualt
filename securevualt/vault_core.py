"""
vault_core.py — Cryptographic core for SecureVault 
built by Ido
Fixed issues from original:
  1. save() now correctly writes the real salt (not master_key bytes)
  2. Backup is encrypted with a separate nonce, not raw key material
  3. Key derivation uses Argon2id directly via argon2-cffi (no SHA256 wrapper)
  4. Passwords are cleared from memory after use where possible
"""

import os
import json
import secrets
import ctypes
from pathlib import Path
from datetime import datetime, timezone
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SALT_LEN   = 32  
NONCE_LEN  = 12  
FILE_MAGIC = b"SV1"  

ARGON2_TIME_COST   = 3
ARGON2_MEMORY_COST = 65536 
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN    = 32   

VAULT_VERSION = 1


def _zero_bytes(buf: bytearray):
    """Overwrite a bytearray with zeros to reduce time secret material stays in memory."""
    for i in range(len(buf)):
        buf[i] = 0


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Argon2id key derivation.
    Returns 32 raw key bytes suitable for AES-256-GCM.
    Uses argon2-cffi's low-level API which avoids the PHC string overhead.
    """
    raw_pw = password.encode("utf-8")
    key = hash_secret_raw(
        secret=raw_pw,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
    pw_ba = bytearray(raw_pw)
    _zero_bytes(pw_ba)
    return key


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce || ciphertext+tag."""
    nonce = secrets.token_bytes(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt(key: bytes, data: bytes) -> bytes:
    """AES-256-GCM decrypt. Raises InvalidTag on wrong key/tampered data."""
    nonce, ct = data[:NONCE_LEN], data[NONCE_LEN:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)



class VaultError(Exception):
    pass

class WrongPasswordError(VaultError):
    pass

class TamperedVaultError(VaultError):
    pass


class SecureVault:
    """
    File format (binary):
        3  bytes  magic  "SV1"
        1  byte   version (0x01)
        32 bytes  Argon2id salt
        12 bytes  AES-GCM nonce
        N  bytes  AES-GCM ciphertext+tag (of UTF-8 JSON payload)

    Backup file: same format, different nonce.
    """

    def __init__(self, vault_path: str = "vault.sv1"):
        self.vault_path = Path(vault_path)
        self._key: bytes | None = None
        self._salt: bytes | None = None
        self._data: dict = {}
        self.is_unlocked = False


    def create(self, master_password: str) -> None:
        """Create a brand-new vault file. Raises if file already exists."""
        if self.vault_path.exists():
            raise VaultError(f"Vault already exists at {self.vault_path}")
        self._salt = secrets.token_bytes(SALT_LEN)
        self._key  = derive_key(master_password, self._salt)
        self._data = {}
        self.is_unlocked = True
        self._write_vault()

    def unlock(self, master_password: str) -> None:
        """Unlock an existing vault. Raises WrongPasswordError or TamperedVaultError."""
        if not self.vault_path.exists():
            raise VaultError(f"No vault found at {self.vault_path}")
        raw = self.vault_path.read_bytes()
        self._load_raw(raw, master_password)
        self.is_unlocked = True

    def lock(self) -> None:
        """Wipe key material from memory."""
        if self._key:
            key_ba = bytearray(self._key)
            _zero_bytes(key_ba)
        self._key = None
        self._data = {}
        self.is_unlocked = False

    def change_master_password(self, old_pw: str, new_pw: str) -> None:
        self._require_unlocked()
        # Re-derive with new salt & password
        self._salt = secrets.token_bytes(SALT_LEN)
        self._key  = derive_key(new_pw, self._salt)
        self._write_vault()


    def add(self, service: str, username: str, password: str,
            notes: str = "", totp_secret: str = "") -> None:
        self._require_unlocked()
        now = datetime.now(timezone.utc).isoformat()
        self._data[service] = {
            "username":    username,
            "password":    password,
            "notes":       notes,
            "totp_secret": totp_secret,
            "created":     now,
            "modified":    now,
        }
        self._write_vault()

    def update(self, service: str, **fields) -> None:
        self._require_unlocked()
        if service not in self._data:
            raise KeyError(f"Service '{service}' not found")
        allowed = {"username", "password", "notes", "totp_secret"}
        for k, v in fields.items():
            if k not in allowed:
                raise ValueError(f"Unknown field: {k}")
            self._data[service][k] = v
        self._data[service]["modified"] = datetime.now(timezone.utc).isoformat()
        self._write_vault()

    def delete(self, service: str) -> None:
        self._require_unlocked()
        self._data.pop(service, None)
        self._write_vault()

    def get(self, service: str) -> dict | None:
        self._require_unlocked()
        return self._data.get(service)

    def list_services(self) -> list[str]:
        self._require_unlocked()
        return sorted(self._data.keys())

    def search(self, query: str) -> list[str]:
        self._require_unlocked()
        q = query.lower()
        return [s for s in self._data if q in s.lower()
                or q in self._data[s].get("username", "").lower()
                or q in self._data[s].get("notes", "").lower()]


    def _require_unlocked(self):
        if not self.is_unlocked or self._key is None:
            raise VaultError("Vault is locked. Call unlock() first.")

    def _write_vault(self):
        """Serialize → encrypt → write (atomic via temp file)."""
        plaintext = json.dumps(self._data, ensure_ascii=False).encode("utf-8")
        blob = encrypt(self._key, plaintext)
        payload = FILE_MAGIC + bytes([VAULT_VERSION]) + self._salt + blob

        tmp = self.vault_path.with_suffix(".tmp")
        tmp.write_bytes(payload)
        tmp.replace(self.vault_path)

        blob_bak = encrypt(self._key, plaintext)
        payload_bak = FILE_MAGIC + bytes([VAULT_VERSION]) + self._salt + blob_bak
        self.vault_path.with_suffix(".bak").write_bytes(payload_bak)

    def _load_raw(self, raw: bytes, password: str):
        if raw[:3] != FILE_MAGIC:
            raise TamperedVaultError("Invalid vault magic bytes")
        version = raw[3]
        if version != VAULT_VERSION:
            raise VaultError(f"Unsupported vault version: {version}")

        offset   = 4
        salt     = raw[offset:offset + SALT_LEN];  offset += SALT_LEN
        blob     = raw[offset:]  # nonce + ct+tag

        key = derive_key(password, salt)
        try:
            plaintext = decrypt(key, blob)
        except Exception:
            raise WrongPasswordError("Wrong master password or vault is corrupted")

        self._salt = salt
        self._key  = key
        self._data = json.loads(plaintext.decode("utf-8"))
