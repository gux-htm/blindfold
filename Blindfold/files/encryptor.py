import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 64 KB chunk size for RAM-efficient stream processing
CHUNK_SIZE = 64 * 1024  

class FileEncryptor:
    """
    Upgraded AES-256-GCM chunked file encryption pipeline.
    Replaces EncryptXpert's older AES-EAX implementation.
    Processes files in chunks to support arbitrarily large files without exhausting RAM.
    Binds chunk index to AAD to prevent chunk reordering/truncation attacks.
    """
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        self.aesgcm = AESGCM(key)

    def encrypt_file(self, input_path: str, output_path: str):
        """Encrypts a file in chunks using AES-GCM."""
        in_path = Path(input_path).expanduser()
        out_path = Path(output_path).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(in_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
            chunk_index = 0
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                # 96-bit nonce for AES-GCM
                nonce = os.urandom(12)
                
                # Bind chunk index to Associated Data to prevent chunk reordering
                aad = chunk_index.to_bytes(8, 'little')
                
                ciphertext = self.aesgcm.encrypt(nonce, chunk, aad)
                
                # Write frame: [Payload Length (4B)] + [Nonce (12B)] + [Ciphertext + Tag]
                length_bytes = len(ciphertext).to_bytes(4, 'little')
                f_out.write(length_bytes + nonce + ciphertext)
                
                chunk_index += 1

    def decrypt_file(self, input_path: str, output_path: str):
        """Decrypts a chunked AES-GCM file."""
        in_path = Path(input_path).expanduser()
        out_path = Path(output_path).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(in_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
            chunk_index = 0
            while True:
                length_bytes = f_in.read(4)
                if not length_bytes:
                    break # EOF
                    
                length = int.from_bytes(length_bytes, 'little')
                nonce = f_in.read(12)
                ciphertext = f_in.read(length)
                
                if len(nonce) != 12 or len(ciphertext) != length:
                    raise ValueError("Encrypted file is corrupted or truncated.")
                    
                aad = chunk_index.to_bytes(8, 'little')
                
                try:
                    plaintext = self.aesgcm.decrypt(nonce, ciphertext, aad)
                except Exception as e:
                    raise ValueError(f"MAC verification failed at chunk {chunk_index}: {e}")
                
                f_out.write(plaintext)
                chunk_index += 1
