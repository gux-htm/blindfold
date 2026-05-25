import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class SecureShredder:
    """
    Implements DoD 5220.22-M 3-pass secure overwrite for local files.
    Pass 1: Overwrite with zeros (0x00)
    Pass 2: Overwrite with ones (0xFF)
    Pass 3: Overwrite with cryptographically secure random bytes
    Finally, deletes the file.
    """
    
    @staticmethod
    def _overwrite_pass(filepath: Path, file_size: int, byte_pattern: bytes):
        """Perform a single overwrite pass with the given byte pattern."""
        chunk_size = 64 * 1024
        # If byte_pattern is length > 1, we interpret it as a flag to generate random data
        is_random = len(byte_pattern) > 1
        
        with open(filepath, 'r+b') as f:
            bytes_written = 0
            while bytes_written < file_size:
                write_size = min(chunk_size, file_size - bytes_written)
                
                if is_random:
                    chunk = os.urandom(write_size)
                else:
                    chunk = byte_pattern * write_size
                    
                f.write(chunk)
                bytes_written += write_size
            f.flush()
            os.fsync(f.fileno())

    @staticmethod
    def shred_file(filepath: str):
        path = Path(filepath).expanduser()
        if not path.exists() or not path.is_file():
            logger.warning(f"File {path} does not exist for shredding.")
            return

        file_size = path.stat().st_size
        if file_size == 0:
            path.unlink()
            return

        try:
            # Pass 1: Zeros
            SecureShredder._overwrite_pass(path, file_size, b'\x00')
            # Pass 2: Ones
            SecureShredder._overwrite_pass(path, file_size, b'\xff')
            # Pass 3: Random
            SecureShredder._overwrite_pass(path, file_size, b'random_flag') 
            
            # Finally, delete the file from the filesystem
            path.unlink()
            logger.info(f"Successfully shredded {path}")
            
        except Exception as e:
            logger.error(f"Failed to securely shred {path}: {e}")
            raise
