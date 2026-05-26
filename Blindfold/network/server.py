import logging
import socket
import struct
import cbor2
from PySide6.QtCore import QThread, Signal
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

GLOBAL_MAC_KEY = b"blindfold_global_transport_key_32"

logger = logging.getLogger(__name__)

def recv_exactly(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise Exception("Connection closed prematurely")
        data += chunk
    return data

def recv_and_unpack_frame(sock) -> tuple[dict, bytes]:
    """Unpack and authenticate a transport frame (compatible with transport.py format)."""
    # 1. Read prefix (14 bytes)
    prefix = recv_exactly(sock, 14)
    magic, version, flags, hlen, plen = struct.unpack("!4sBBII", prefix)
    
    if magic != b"PLNK":
        raise Exception("Invalid magic bytes")
    if version != 1:
        raise Exception("Unsupported protocol version")
        
    # 2. Read CBOR header + payload + 16 bytes MAC
    body_mac = recv_exactly(sock, hlen + plen + 16)
    body = body_mac[:-16]
    mac = body_mac[-16:]
    
    # 3. Verify integrity tag using ChaCha20-Poly1305 over AAD=prefix+body
    chacha = ChaCha20Poly1305(GLOBAL_MAC_KEY)
    nonce = (0).to_bytes(12, 'little')
    chacha.decrypt(nonce, mac, prefix + body) # returns b"" on success, raises Exception on failure
    
    # 4. Parse header and return
    header_bytes = body[:hlen]
    payload = body[hlen:]
    
    header = cbor2.loads(header_bytes)
    return header, payload

class ChatServerThread(QThread):
    message_received = Signal(str, str) # sender_onion, plaintext_message
    log_message = Signal(str)

    def __init__(self, db, session_mgr, host="127.0.0.1", port=8080):
        super().__init__()
        self.db = db
        self.session_mgr = session_mgr
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None

    def run(self):
        self.running = True
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.server_socket.settimeout(1.0) # non-blocking accept loop
            
            logger.info(f"ChatServer listening on {self.host}:{self.port}...")
            self.log_message.emit(f"Server started on port {self.port}.")
            
            while self.running:
                try:
                    sock, addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Accept error: {e}")
                    continue
                
                # Handle connection synchronously (very brief exchange)
                sock.settimeout(10.0)
                try:
                    header, ciphertext = recv_and_unpack_frame(sock)
                    
                    sender_onion = header.get("sender_onion")
                    sender_pubkey = header.get("sender_pubkey")
                    dh_pub = header.get("dh_pub")
                    pn = header.get("pn")
                    n = header.get("n")
                    
                    if not sender_onion or not sender_pubkey:
                        raise Exception("Missing sender identity in frame header")
                        
                    logger.info(f"Incoming connection from {sender_onion} ({sender_pubkey.hex()})")
                    
                    # Ensure sender exists in contacts database
                    contact = self.db.get("contacts", sender_onion)
                    if not contact:
                        # Auto-create contact for Trust-on-First-Use (TOFU)
                        name = f"Peer_{sender_onion[:8]}"
                        logger.info(f"Auto-creating contact {name} for {sender_onion}")
                        self.db.put("contacts", sender_onion, {
                            "name": name,
                            "pubkey": sender_pubkey.hex()
                        })
                    
                    # Load or initialize ratchet session
                    ratchet = self.session_mgr.get_session(sender_onion)
                    if not ratchet:
                        logger.info(f"Initializing a new Bob session for {sender_onion}")
                        ratchet = self.session_mgr.initialize_bob_session(sender_onion, sender_pubkey.hex())
                        
                    # Decrypt using Double Ratchet
                    plaintext_bytes = ratchet.ratchet_decrypt(dh_pub, pn, n, ciphertext)
                    self.session_mgr.save_session(sender_onion, ratchet)
                    
                    plaintext = plaintext_bytes.decode('utf-8')
                    logger.info(f"Successfully decrypted message from {sender_onion}: {plaintext}")
                    
                    # Emit received message
                    self.message_received.emit(sender_onion, plaintext)
                    
                except Exception as e:
                    logger.error(f"Error handling incoming message connection: {e}")
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass
                        
        except Exception as e:
            logger.error(f"Server crash: {e}")
            self.log_message.emit(f"Server crash: {e}")
        finally:
            if self.server_socket:
                try:
                    self.server_socket.close()
                except Exception:
                    pass
            logger.info("ChatServer stopped.")

    def stop(self):
        self.running = False
        self.wait()
