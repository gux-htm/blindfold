"""
Blindfold Cryptographic Primitives (Upgraded)
Implements Ed25519, X25519, XSalsa20-Poly1305, AES-256-GCM, ChaCha20-Poly1305, HKDF-SHA512, Argon2id.
"""
import os
import nacl.secret
import nacl.exceptions
import nacl.hash
import nacl.encoding
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM

# argon2-cffi
import argon2
from argon2.exceptions import VerifyMismatchError

class InvalidToken(Exception):
    """Raised when decryption fails (wrong key, tampered ciphertext)."""

class _NaClBox:
    """XSalsa20-Poly1305 secretbox wrapper."""
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError(f"_NaClBox requires a 32-byte key, got {len(key)}")
        self._box = nacl.secret.SecretBox(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        return bytes(self._box.encrypt(plaintext))

    def decrypt(self, token: bytes) -> bytes:
        try:
            return bytes(self._box.decrypt(token))
        except nacl.exceptions.CryptoError as e:
            raise InvalidToken("Decryption failed") from e

def hkdf_derive(secret: bytes, info: str, salt: bytes = None, length: int = 32) -> bytes:
    """HKDF-SHA512 Key Derivation Function. Upgraded from BLAKE2b KDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=salt,
        info=info.encode("utf-8"),
    )
    return hkdf.derive(secret)

def b2b_mac(key: bytes, message: str) -> str:
    """BLAKE2b keyed MAC. Returns hex string."""
    return nacl.hash.blake2b(
        message.encode("utf-8"),
        key=key,
        digest_size=32,
        encoder=nacl.encoding.HexEncoder,
    ).decode()

def b2b_verify(key: bytes, message: str, mac_hex: str) -> bool:
    """Verify BLAKE2b MAC in constant time."""
    try:
        expected = bytes.fromhex(b2b_mac(key, message))
        received = bytes.fromhex(mac_hex)
        return hmac.compare_digest(expected, received)
    except (ValueError, Exception):
        return False

def hash_argon2id(password: str, salt: bytes) -> bytes:
    """Derive a key from password using Argon2id. (64MB RAM, 3 iterations, 2 parallelism)"""
    # argon2-cffi low-level API to get raw hash
    return argon2.low_level.hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=3,
        memory_cost=65536, # 64MB
        parallelism=2,
        hash_len=32,
        type=argon2.low_level.Type.ID
    )

# --- File Encryption (Upgraded from EncryptXpert) ---

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encryption for file chunks. Returns nonce(12) + ciphertext + tag(16)"""
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)

def aes_gcm_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-256-GCM decryption for file chunks."""
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    if len(data) < 28:
        raise InvalidToken("Ciphertext too short")
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(data[:12], data[12:], None)
    except Exception as e:
        raise InvalidToken("AES-GCM decryption failed") from e

# --- Key Wrapping ---

def wrap_key(kek: bytes, raw_key: bytes) -> bytes:
    """Wrap (encrypt) a file key using ChaCha20-Poly1305 over a Key Encryption Key."""
    chacha = ChaCha20Poly1305(kek)
    nonce = os.urandom(12)
    return nonce + chacha.encrypt(nonce, raw_key, None)

def unwrap_key(kek: bytes, wrapped_data: bytes) -> bytes:
    """Unwrap a file key."""
    if len(wrapped_data) < 28:
        raise InvalidToken("Wrapped key data too short")
    chacha = ChaCha20Poly1305(kek)
    try:
        return chacha.decrypt(wrapped_data[:12], wrapped_data[12:], None)
    except Exception as e:
        raise InvalidToken("Key unwrapping failed") from e

# --- Identity (Ed25519) ---

def generate_identity() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair. Returns (sk_bytes, vk_bytes)."""
    sk = Ed25519PrivateKey.generate()
    sk_bytes = sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    vk_bytes = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return sk_bytes, vk_bytes

def sign_message(sk_bytes: bytes, data: bytes) -> bytes:
    """Sign data with Ed25519. Returns 64-byte signature."""
    return Ed25519PrivateKey.from_private_bytes(sk_bytes).sign(data)

def verify_signature(vk_bytes: bytes, data: bytes, sig_bytes: bytes) -> bool:
    """Verify an Ed25519 signature."""
    try:
        Ed25519PublicKey.from_public_bytes(vk_bytes).verify(sig_bytes, data)
        return True
    except Exception:
        return False

# --- Key Exchange (X25519) ---

def dh_generate_keypair() -> tuple[bytes, bytes]:
    """Generate ephemeral X25519 keypair. Returns (priv_bytes, pub_bytes)."""
    priv = X25519PrivateKey.generate()
    return (
        priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ),
    )

def dh_exchange(my_priv_bytes: bytes, peer_pub_bytes: bytes) -> bytes:
    """X25519 DH exchange. Returns shared secret."""
    return X25519PrivateKey.from_private_bytes(my_priv_bytes).exchange(
        X25519PublicKey.from_public_bytes(peer_pub_bytes)
    )

def dh_derive_shared_box(my_priv_bytes: bytes, peer_pub_bytes: bytes) -> tuple[_NaClBox, bytes]:
    """X25519 DH -> HKDF-SHA512 -> XSalsa20-Poly1305 box."""
    shared = dh_exchange(my_priv_bytes, peer_pub_bytes)
    key_material = hkdf_derive(shared, "pairwise_v2")
    return _NaClBox(key_material), key_material
