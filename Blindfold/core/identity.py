import json
import os
import subprocess
from pathlib import Path
from core.crypto import generate_identity, hash_argon2id, _NaClBox, InvalidToken, hkdf_derive
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def get_device_fingerprint() -> bytes:
    """Get a device-specific fingerprint to bind the vault."""
    try:
        if os.name == 'nt':
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                return guid.encode()
        else:
            # Linux fallback
            with open('/etc/machine-id', 'rb') as f:
                return f.read().strip()
    except Exception:
        # Fallback to a fixed salt if extraction fails
        return b"blindfold_fallback_device_binding"

def _derive_vault_box(password: str, salt: bytes, device_fp: bytes) -> _NaClBox:
    """Derive XSalsa20-Poly1305 box from Argon2id(password) + HKDF(device_fp)."""
    # First get the Root Key from Argon2id
    root_key = hash_argon2id(password, salt)
    
    # Bind to device using HKDF-SHA512
    vault_key = hkdf_derive(root_key, "blindfold_vault_v1", salt=device_fp)
    
    return _NaClBox(vault_key)

def create_identity_vault(path: str, password: str) -> tuple[bytes, bytes]:
    """Create a new identity and store it encrypted in the vault."""
    sk_bytes, vk_bytes = generate_identity()
    
    salt = os.urandom(32)
    device_fp = get_device_fingerprint()
    
    box = _derive_vault_box(password, salt, device_fp)
    
    payload = {
        "v": 1,
        "vk_hex": vk_bytes.hex(),
        "salt": salt.hex(),
        "sk_enc": box.encrypt(sk_bytes).hex(),
    }
    
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload))
    
    if os.name != 'nt':
        p.chmod(0o600)
        
    return sk_bytes, vk_bytes

def load_identity_vault(path: str, password: str) -> tuple[bytes, bytes]:
    """Load identity from vault."""
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError("Vault not found.")
        
    data = json.loads(p.read_text())
    vk_bytes = bytes.fromhex(data["vk_hex"])
    salt = bytes.fromhex(data["salt"])
    sk_enc = bytes.fromhex(data["sk_enc"])
    
    device_fp = get_device_fingerprint()
    box = _derive_vault_box(password, salt, device_fp)
    
    try:
        sk_bytes = box.decrypt(sk_enc)
        return sk_bytes, vk_bytes
    except InvalidToken:
        raise ValueError("Incorrect password or device mismatch.")

def unlock_or_create_vault(password: str) -> tuple[bytes, bytes]:
    """
    Attempts to load the identity vault with the given password.
    If it doesn't exist, it creates one.
    Returns (sk_bytes, vk_bytes) where sk_bytes acts as the master root key for the app.
    """
    path = "~/.blindfold/identity.json"
    p = Path(path).expanduser()
    
    if p.exists():
        sk_bytes, vk_bytes = load_identity_vault(path, password)
        return sk_bytes, vk_bytes
    else:
        sk_bytes, vk_bytes = create_identity_vault(path, password)
        return sk_bytes, vk_bytes

def generate_invite_code(onion_address: str, pubkey_hex: str) -> str:
    """Consolidate onion address and pubkey hex into a single base64 blindfold:// link."""
    import base64
    import json
    payload = {
        "onion": onion_address,
        "pubkey": pubkey_hex
    }
    json_bytes = json.dumps(payload).encode('utf-8')
    b64_str = base64.b64encode(json_bytes).decode('utf-8')
    return f"blindfold://{b64_str}"

def parse_invite_code(invite_code: str) -> tuple[str, str]:
    """Parse a consolidated blindfold:// invite code into (onion_address, pubkey_hex)."""
    import base64
    import json
    invite_code = invite_code.strip()
    if not invite_code.startswith("blindfold://"):
        raise ValueError("Invalid invite code format (must start with blindfold://)")
    
    b64_str = invite_code.replace("blindfold://", "")
    json_bytes = base64.b64decode(b64_str.encode('utf-8'))
    payload = json.loads(json_bytes.decode('utf-8'))
    
    onion = payload["onion"]
    pubkey = payload["pubkey"]
    
    if isinstance(onion, list):
        onion = onion[0]
        
    if not onion.endswith(".onion") or len(pubkey) != 64:
        raise ValueError("Invalid credentials inside invite code")
        
    return onion, pubkey

