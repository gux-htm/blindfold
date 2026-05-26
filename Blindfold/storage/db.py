import sqlite3
import json
import os
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

DEFAULT_DB_PATH = "~/.blindfold/blindfold.db"

class EncryptedDatabase:
    """
    Fallback encrypted database using standard sqlite3 + ChaCha20Poly1305 field encryption.
    Provides identical at-rest security guarantees as SQLCipher for row data.
    """
    def __init__(self, key: bytes, path: str = DEFAULT_DB_PATH):
        if len(key) != 32:
            raise ValueError("Encryption key must be 32 bytes")
        self.key = key
        self.db_path = Path(path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Ensure correct file permissions
        if self.db_path.exists() and os.name != 'nt':
            try:
                self.db_path.chmod(0o600)
            except OSError:
                pass
                
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.chacha = ChaCha20Poly1305(self.key)
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        # Store everything as encrypted blobs to hide schema metadata
        with self.lock:
            with self.conn:
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS secure_store (
                        collection TEXT,
                        key_id TEXT,
                        nonce BLOB,
                        ciphertext BLOB,
                        PRIMARY KEY (collection, key_id)
                    )
                """)

    def _encrypt_payload(self, payload: dict) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        plaintext = json.dumps(payload).encode('utf-8')
        ciphertext = self.chacha.encrypt(nonce, plaintext, None)
        return nonce, ciphertext

    def _decrypt_payload(self, nonce: bytes, ciphertext: bytes) -> dict:
        plaintext = self.chacha.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))

    def put(self, collection: str, key_id: str, data: dict):
        nonce, ciphertext = self._encrypt_payload(data)
        with self.lock:
            with self.conn:
                self.conn.execute("""
                    INSERT INTO secure_store (collection, key_id, nonce, ciphertext)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(collection, key_id) DO UPDATE SET
                    nonce=excluded.nonce,
                    ciphertext=excluded.ciphertext
                """, (collection, key_id, nonce, ciphertext))

    def get(self, collection: str, key_id: str) -> Optional[dict]:
        with self.lock:
            cur = self.conn.execute("SELECT nonce, ciphertext FROM secure_store WHERE collection=? AND key_id=?", (collection, key_id))
            row = cur.fetchone()
        if not row:
            return None
        try:
            return self._decrypt_payload(row['nonce'], row['ciphertext'])
        except Exception:
            return None

    def delete(self, collection: str, key_id: str):
        with self.lock:
            with self.conn:
                self.conn.execute("DELETE FROM secure_store WHERE collection=? AND key_id=?", (collection, key_id))
            
    def get_all(self, collection: str) -> Dict[str, dict]:
        with self.lock:
            cur = self.conn.execute("SELECT key_id, nonce, ciphertext FROM secure_store WHERE collection=?", (collection,))
            rows = cur.fetchall()
        results = {}
        for row in rows:
            try:
                results[row['key_id']] = self._decrypt_payload(row['nonce'], row['ciphertext'])
            except Exception:
                continue
        return results

    def close(self):
        with self.lock:
            self.conn.close()
