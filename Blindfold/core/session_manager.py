import logging
from core.ratchet import DoubleRatchet
from core.crypto import ed25519_sk_to_x25519, ed25519_pk_to_x25519, dh_exchange
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

def x25519_sk_to_pk(priv_bytes: bytes) -> bytes:
    """Derive X25519 public key from private key bytes."""
    return X25519PrivateKey.from_private_bytes(priv_bytes).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

class SessionManager:
    def __init__(self, master_key: bytes, db):
        self.master_key = master_key  # Our own Ed25519 seed/private key (32 bytes)
        self.db = db

    def get_session(self, contact_onion: str) -> DoubleRatchet:
        """Load session for a contact from database. Returns None if it doesn't exist."""
        state = self.db.get("ratchet_states", contact_onion)
        if not state:
            return None
        
        try:
            ratchet = DoubleRatchet()
            ratchet.dhs_priv = bytes.fromhex(state["dhs_priv"]) if state["dhs_priv"] else None
            ratchet.dhs_pub = bytes.fromhex(state["dhs_pub"]) if state["dhs_pub"] else None
            ratchet.dhr_pub = bytes.fromhex(state["dhr_pub"]) if state["dhr_pub"] else None
            ratchet.rk = bytes.fromhex(state["rk"]) if state["rk"] else None
            ratchet.ck_s = bytes.fromhex(state["ck_s"]) if state["ck_s"] else None
            ratchet.ck_r = bytes.fromhex(state["ck_r"]) if state["ck_r"] else None
            ratchet.n_s = state["n_s"]
            ratchet.n_r = state["n_r"]
            ratchet.pn = state["pn"]
            
            mkskipped = {}
            for k, v in state.get("mkskipped", {}).items():
                dh_hex, n_str = k.split(":")
                mkskipped[(dh_hex, int(n_str))] = bytes.fromhex(v)
            ratchet.mkskipped = mkskipped
            return ratchet
        except Exception as e:
            logger.error(f"Failed to deserialize ratchet state for {contact_onion}: {e}")
            return None

    def initialize_alice_session(self, contact_onion: str, peer_pubkey_hex: str) -> DoubleRatchet:
        """Initialize session as Alice (sender)."""
        # Convert keys
        my_x25519_sk = ed25519_sk_to_x25519(self.master_key)
        peer_x25519_pk = ed25519_pk_to_x25519(bytes.fromhex(peer_pubkey_hex))
        
        # Calculate shared secret
        sk = dh_exchange(my_x25519_sk, peer_x25519_pk)
        
        ratchet = DoubleRatchet()
        ratchet.init_alice(sk, peer_x25519_pk)
        
        self.save_session(contact_onion, ratchet)
        return ratchet

    def initialize_bob_session(self, contact_onion: str, peer_pubkey_hex: str) -> DoubleRatchet:
        """Initialize session as Bob (receiver)."""
        # Convert keys
        my_x25519_sk = ed25519_sk_to_x25519(self.master_key)
        my_x25519_pk = x25519_sk_to_pk(my_x25519_sk)
        peer_x25519_pk = ed25519_pk_to_x25519(bytes.fromhex(peer_pubkey_hex))
        
        # Calculate shared secret
        sk = dh_exchange(my_x25519_sk, peer_x25519_pk)
        
        ratchet = DoubleRatchet()
        ratchet.init_bob(sk, my_x25519_sk, my_x25519_pk)
        
        self.save_session(contact_onion, ratchet)
        return ratchet

    def save_session(self, contact_onion: str, ratchet: DoubleRatchet):
        """Save active ratchet session to the database."""
        state = {
            "dhs_priv": ratchet.dhs_priv.hex() if ratchet.dhs_priv else None,
            "dhs_pub": ratchet.dhs_pub.hex() if ratchet.dhs_pub else None,
            "dhr_pub": ratchet.dhr_pub.hex() if ratchet.dhr_pub else None,
            "rk": ratchet.rk.hex() if ratchet.rk else None,
            "ck_s": ratchet.ck_s.hex() if ratchet.ck_s else None,
            "ck_r": ratchet.ck_r.hex() if ratchet.ck_r else None,
            "n_s": ratchet.n_s,
            "n_r": ratchet.n_r,
            "pn": ratchet.pn,
            "mkskipped": {f"{k[0]}:{k[1]}": v.hex() for k, v in ratchet.mkskipped.items()}
        }
        self.db.put("ratchet_states", contact_onion, state)
