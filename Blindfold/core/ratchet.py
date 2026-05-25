"""
Double Ratchet (Signal Protocol) Implementation for Blindfold.
Provides forward secrecy and break-in recovery for 1-to-1 direct messages.
"""

import os
from typing import Optional, Tuple
from core.crypto import hkdf_derive, _NaClBox, dh_generate_keypair, dh_exchange, InvalidToken

# Domain separation constants for HKDF
INFO_RATCHET_ROOT = "blindfold_ratchet_root"
INFO_RATCHET_CHAIN = "blindfold_ratchet_chain"
INFO_RATCHET_MSG = "blindfold_ratchet_msg"

def kdf_rk(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """Root Key Derivation. Returns (new_root_key, chain_key)."""
    derived = hkdf_derive(dh_out, INFO_RATCHET_ROOT, salt=rk, length=64)
    return derived[:32], derived[32:]

def kdf_ck(ck: bytes) -> Tuple[bytes, bytes]:
    """Chain Key Derivation. Returns (new_chain_key, message_key).
    Uses HMAC/HKDF, but we can just use HKDF with constant salt/info for simplicity.
    """
    derived = hkdf_derive(ck, INFO_RATCHET_CHAIN, length=64)
    return derived[:32], derived[32:]

class DoubleRatchet:
    def __init__(self):
        # DH State
        self.dhs_priv: Optional[bytes] = None
        self.dhs_pub: Optional[bytes] = None
        self.dhr_pub: Optional[bytes] = None
        
        # KDF State
        self.rk: Optional[bytes] = None
        self.ck_s: Optional[bytes] = None
        self.ck_r: Optional[bytes] = None
        
        # Message counts
        self.n_s: int = 0
        self.n_r: int = 0
        self.pn: int = 0 # Number of msgs in previous sending chain
        
        # Dictionary of skipped message keys: (dh_pub_hex, n_r) -> msg_key
        self.mkskipped: dict[Tuple[str, int], bytes] = {}

    def init_alice(self, sk: bytes, bob_dh_pub: bytes):
        """Initialize as Alice (initiator). sk is the shared secret."""
        self.dhs_priv, self.dhs_pub = dh_generate_keypair()
        self.dhr_pub = bob_dh_pub
        
        dh_out = dh_exchange(self.dhs_priv, self.dhr_pub)
        self.rk, self.ck_s = kdf_rk(sk, dh_out)

    def init_bob(self, sk: bytes, bob_dh_priv: bytes, bob_dh_pub: bytes):
        """Initialize as Bob (receiver)."""
        self.dhs_priv = bob_dh_priv
        self.dhs_pub = bob_dh_pub
        self.rk = sk

    def ratchet_encrypt(self, plaintext: bytes, ad: bytes = b"") -> Tuple[bytes, bytes, int, int]:
        """Encrypt a message. Returns (header_dh_pub, ciphertext, pn, n_s)."""
        if self.ck_s is None:
             raise RuntimeError("Sending chain not initialized")
             
        self.ck_s, mk = kdf_ck(self.ck_s)
        header = (self.dhs_pub, self.pn, self.n_s)
        self.n_s += 1
        
        # In a real implementation, 'ad' (Associated Data) should be authenticated.
        # Here we just encrypt with the message key using NaClBox (XSalsa20-Poly1305).
        # We append 'ad' to plaintext or handle it at the protocol level.
        box = _NaClBox(mk)
        ciphertext = box.encrypt(plaintext)
        return self.dhs_pub, ciphertext, header[1], header[2]

    def ratchet_decrypt(self, header_dh_pub: bytes, pn: int, n: int, ciphertext: bytes, ad: bytes = b"") -> bytes:
        """Decrypt a message."""
        # Check if it's a skipped message
        mk = self.mkskipped.get((header_dh_pub.hex(), n))
        if mk:
            del self.mkskipped[(header_dh_pub.hex(), n)]
            return self._decrypt_with_mk(mk, ciphertext)

        # New DH ratchet step
        if header_dh_pub != self.dhr_pub:
            self._skip_message_keys(self.pn)
            self._dh_ratchet(header_dh_pub)

        # Skip message keys in the current receiving chain
        self._skip_message_keys(n)
        
        self.ck_r, mk = kdf_ck(self.ck_r)
        self.n_r += 1
        return self._decrypt_with_mk(mk, ciphertext)

    def _decrypt_with_mk(self, mk: bytes, ciphertext: bytes) -> bytes:
        box = _NaClBox(mk)
        return box.decrypt(ciphertext)

    def _skip_message_keys(self, until_n: int):
        if self.ck_r is None:
            return
        while self.n_r < until_n:
            self.ck_r, mk = kdf_ck(self.ck_r)
            self.mkskipped[(self.dhr_pub.hex(), self.n_r)] = mk
            self.n_r += 1

    def _dh_ratchet(self, header_dh_pub: bytes):
        self.pn = self.n_s
        self.n_s = 0
        self.n_r = 0
        self.dhr_pub = header_dh_pub
        
        dh_out = dh_exchange(self.dhs_priv, self.dhr_pub)
        self.rk, self.ck_r = kdf_rk(self.rk, dh_out)
        
        self.dhs_priv, self.dhs_pub = dh_generate_keypair()
        dh_out = dh_exchange(self.dhs_priv, self.dhr_pub)
        self.rk, self.ck_s = kdf_rk(self.rk, dh_out)
