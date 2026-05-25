import json
import hashlib
from pathlib import Path
import os

DEFAULT_TOFU_PATH = "~/.blindfold/tofu_pubkeys.json"

def load_tofu(path: str = DEFAULT_TOFU_PATH) -> dict:
    p = Path(path).expanduser()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}

def save_tofu(store: dict, path: str = DEFAULT_TOFU_PATH) -> None:
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(store, indent=2))
    if os.name != 'nt':
        try:
            p.chmod(0o600)
        except OSError:
            pass

def trust_or_verify(
    store: dict,
    contact_id: str,
    vk_hex: str,
    path: str = DEFAULT_TOFU_PATH,
) -> tuple[bool, bool]:
    """
    Returns (trusted: bool, is_new: bool)
    """
    if contact_id not in store:
        store[contact_id] = vk_hex
        save_tofu(store, path)
        return True, True

    if store[contact_id] == vk_hex:
        return True, False

    return False, False

def compute_safety_number(my_vk_hex: str, peer_vk_hex: str) -> str:
    """Compute a Safety Number for out-of-band verification.
    For MVP, we use numeric chunks. Future versions will use BIP39 words.
    """
    keys = sorted([my_vk_hex, peer_vk_hex])
    combined = (keys[0] + keys[1]).encode('utf-8')
    digest = hashlib.sha512(combined).hexdigest()
    
    # Use part of the digest to create a 20-digit number
    num = str(int(digest[:16], 16))
    num = num.zfill(20)
    
    chunks = [num[i:i+5] for i in range(0, min(20, len(num)), 5)]
    return " ".join(chunks[:4])
