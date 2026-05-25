import os
from typing import Optional
from core.crypto import hkdf_derive
from storage.db import EncryptedDatabase

class VaultKMS:
    """
    Key Management System for wrapping and unwrapping File Encryption Keys (FEK).
    """
    def __init__(self, master_vault_key: bytes, db: EncryptedDatabase):
        # Derive a dedicated KEK (Key Encryption Key) from the master vault key
        # In this implementation, the DB itself uses a key derived from the master key
        # to transparently encrypt fields via ChaCha20Poly1305.
        self.kek = hkdf_derive(
            master_vault_key, 
            info="blindfold_kms_v1", 
            length=32
        )
        self.db = db

    def generate_and_wrap_file_key(self, file_id: str) -> bytes:
        """Generates a fresh 32-byte FEK, stores it securely, and returns the plaintext FEK."""
        fek = os.urandom(32)
        
        # The DB transparently encrypts this dictionary payload with ChaCha20-Poly1305
        # using the database encryption key.
        self.db.put(
            collection="file_keys",
            key_id=file_id,
            data={"fek_hex": fek.hex()}
        )
        return fek

    def unwrap_file_key(self, file_id: str) -> Optional[bytes]:
        """Retrieves and unwraps the FEK from the DB."""
        data = self.db.get(collection="file_keys", key_id=file_id)
        if not data or "fek_hex" not in data:
            return None
        return bytes.fromhex(data["fek_hex"])

    def shred_file_key(self, file_id: str):
        """Permanently deletes the FEK, rendering the encrypted file inaccessible."""
        self.db.delete(collection="file_keys", key_id=file_id)
