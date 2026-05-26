import logging
import socket
import struct
import cbor2
from PySide6.QtCore import QThread, Signal
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

GLOBAL_MAC_KEY = b"blindfold_global_transport_key_32"

logger = logging.getLogger(__name__)

def socks5_connect(socks_host: str, socks_port: int, target_host: str, target_port: int) -> socket.socket:
    """Connect to a target host and port through a SOCKS5 proxy using pure Python socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(60.0)  # Tor connection can take some time
    s.connect((socks_host, socks_port))
    
    # 1. Send SOCKS5 greeting
    s.sendall(b"\x05\x01\x00")
    
    # 2. Read greeting response
    resp = s.recv(2)
    if len(resp) < 2 or resp[0] != 0x05 or resp[1] != 0x00:
        s.close()
        raise Exception("SOCKS5 greeting failed or authentication required")
        
    # 3. Send CONNECT request to domain name
    host_bytes = target_host.encode('ascii')
    req = struct.pack("!BBBBB", 0x05, 0x01, 0x00, 0x03, len(host_bytes)) + host_bytes + struct.pack("!H", target_port)
    s.sendall(req)
    
    # 4. Read response
    resp = s.recv(4)
    if len(resp) < 4 or resp[0] != 0x05 or resp[1] != 0x00:
        s.close()
        raise Exception(f"SOCKS5 connection failed with status code: {resp[1] if len(resp) >= 2 else 'unknown'}")
        
    # Skip bound address details
    addr_type = resp[3]
    if addr_type == 0x01: # IPv4
        s.recv(4 + 2)
    elif addr_type == 0x03: # Domain
        domain_len = s.recv(1)[0]
        s.recv(domain_len + 2)
    elif addr_type == 0x04: # IPv6
        s.recv(16 + 2)
        
    return s

def encrypt_and_pack_frame(header: dict, payload: bytes) -> bytes:
    """Pack and authenticate a transport frame (compatible with transport.py format)."""
    header_bytes = cbor2.dumps(header)
    prefix = struct.pack("!4sBBII", b"PLNK", 1, 0, len(header_bytes), len(payload))
    data = prefix + header_bytes + payload
    
    # Generate MAC tag using ChaCha20-Poly1305 over AAD=data with empty plaintext
    chacha = ChaCha20Poly1305(GLOBAL_MAC_KEY)
    nonce = (0).to_bytes(12, 'little')
    tag = chacha.encrypt(nonce, b"", data) # returns the 16-byte tag since plaintext is empty
    return data + tag

class ChatClientThread(QThread):
    finished = Signal(bool, str) # success, status_message

    def __init__(self, socks_host: str, socks_port: int, my_onion: str, my_pubkey_hex: str, target_onion: str, message: str, db, session_mgr):
        super().__init__()
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.my_onion = my_onion
        self.my_pubkey_hex = my_pubkey_hex
        self.target_onion = target_onion
        self.message = message
        self.db = db
        self.session_mgr = session_mgr

    def run(self):
        try:
            logger.info(f"Preparing to send message to {self.target_onion} via SOCKS5 proxy {self.socks_host}:{self.socks_port}...")
            
            # 1. Retrieve or initialize ratchet session
            ratchet = self.session_mgr.get_session(self.target_onion)
            if not ratchet:
                contact = self.db.get("contacts", self.target_onion)
                if not contact or "pubkey" not in contact:
                    raise Exception(f"No contact public key found for {self.target_onion}")
                peer_pubkey = contact["pubkey"]
                logger.info(f"Initializing a new Alice session for {self.target_onion}")
                ratchet = self.session_mgr.initialize_alice_session(self.target_onion, peer_pubkey)
            
            # 2. Encrypt message via Double Ratchet
            dh_pub, ciphertext, pn, n_s = ratchet.ratchet_encrypt(self.message.encode('utf-8'))
            self.session_mgr.save_session(self.target_onion, ratchet)
            
            # 3. Construct CBOR header
            header = {
                "dh_pub": dh_pub,
                "pn": pn,
                "n": n_s,
                "sender_onion": self.my_onion,
                "sender_pubkey": bytes.fromhex(self.my_pubkey_hex)
            }
            
            # 4. Pack the frame
            frame_bytes = encrypt_and_pack_frame(header, ciphertext)
            
            # 5. Connect to peer's onion service through SOCKS5 proxy on virtual port 80
            logger.info(f"Connecting to {self.target_onion}:80 via SOCKS...")
            sock = socks5_connect(self.socks_host, self.socks_port, self.target_onion, 80)
            
            # 6. Send frame
            logger.info("Connection established, sending frame bytes...")
            sock.sendall(frame_bytes)
            sock.close()
            
            logger.info("Message sent successfully!")
            self.finished.emit(True, "Sent")
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            self.finished.emit(False, str(e))
