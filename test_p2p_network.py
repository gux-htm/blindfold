import sys
import os
import time
import socket
import threading

# Add Blindfold folder to python path so we can import internal modules
sys.path.append(os.path.join(os.path.dirname(__file__), "Blindfold"))

from core.crypto import generate_identity
from core.session_manager import SessionManager
from storage.db import EncryptedDatabase
from anonymity.tor_manager import TorManager
from network.client import socks5_connect, encrypt_and_pack_frame
from network.server import recv_and_unpack_frame

# Global state flags
sent_success = False
received_success = False
running = True

def print_log(msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def bg_server_loop(db, session_mgr):
    global received_success, running
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(("127.0.0.1", 8080))
        server_socket.listen(5)
        server_socket.settimeout(1.0)
        print_log("[Server] TCP Listener started on 127.0.0.1:8080.")
    except Exception as e:
        print_log(f"[Server] Failed to bind to port 8080: {e}")
        print_log("[Server] Please make sure any GUI instances of Blindfold or other processes using port 8080 are closed.")
        running = False
        return

    while running:
        try:
            sock, addr = server_socket.accept()
        except socket.timeout:
            continue
        except Exception:
            break

        sock.settimeout(10.0)
        try:
            print_log("[Server] Incoming connection detected. Reading frame...")
            header, ciphertext = recv_and_unpack_frame(sock)
            
            sender_onion = header.get("sender_onion")
            sender_pubkey = header.get("sender_pubkey")
            dh_pub = header.get("dh_pub")
            pn = header.get("pn")
            n = header.get("n")
            
            print_log(f"[Server] Unpacked frame from {sender_onion}. Restoring session...")
            
            # Ensure contact exists in database
            contact = db.get("contacts", sender_onion)
            if not contact:
                db.put("contacts", sender_onion, {
                    "name": f"Peer_{sender_onion[:8]}",
                    "pubkey": sender_pubkey.hex()
                })
                
            ratchet = session_mgr.get_session(sender_onion)
            if not ratchet:
                print_log("[Server] Initializing fresh Bob session...")
                ratchet = session_mgr.initialize_bob_session(sender_onion, sender_pubkey.hex())
                
            plaintext_bytes = ratchet.ratchet_decrypt(dh_pub, pn, n, ciphertext)
            session_mgr.save_session(sender_onion, ratchet)
            
            message = plaintext_bytes.decode('utf-8')
            print("\n" + "="*50)
            print(f"[SUCCESS] Secure E2EE Message Received!")
            print(f"From Onion: {sender_onion}")
            print(f"Decrypted Content: '{message}'")
            print("="*50 + "\n")
            received_success = True
        except Exception as e:
            print_log(f"[Server] Failed to process incoming frame: {e}")
        finally:
            sock.close()

    server_socket.close()

def main():
    global sent_success, received_success, running
    
    # 1. Clean up old databases
    db_path = "test_diagnostic.db"
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass

    # 2. Instantiate secure sandbox database and session manager
    test_master_key = b"test_diagnostic_master_key_32_by"
    db = EncryptedDatabase(test_master_key, path=db_path)
    
    sk_bytes, vk_bytes = generate_identity()
    session_mgr = SessionManager(sk_bytes, db)

    print("="*70)
    print("      B L I N D F O L D   P 2 P   C O O P E R A T I V E   D I A G N O S T I C")
    print("="*70)
    print_log("Temporary diagnostic identity generated.")
    print(f"[-] My Test PubKey:  {vk_bytes.hex()}")

    # 3. Connect to Tor and start Hidden Service
    print_log("Connecting to Tor control port...")
    tor = TorManager()
    if not tor.connect():
        print_log("[-] No running Tor detected. Attempting to start embedded daemon...")
        if not tor.launch_embedded_tor() or not tor.connect():
            print_log("[FATAL] Tor could not be launched. Exiting.")
            return
            
    print_log("[+] Connected to Tor SOCKS/Control network successfully!")
    print_log("RegisteringEphemeral Hidden Service (virtual port 80 -> local port 8080)...")
    onion = tor.create_ephemeral_hidden_service(8080)
    if not onion:
        print_log("[FATAL] Ephemeral Hidden Service registration failed. Exiting.")
        return
        
    print(f"[+] My Test Onion:   {onion}")
    print("="*70)
    print("Copy the above 'My Test Onion' and 'My Test PubKey' to give to your partner (Kiro).")
    print("="*70)

    # 4. Fire up background listener
    server_thread = threading.Thread(target=bg_server_loop, args=(db, session_mgr), daemon=True)
    server_thread.start()
    time.sleep(1.0) # wait for server to bind

    if not running:
        return

    # 5. Interactively capture peer credentials
    try:
        peer_onion = input("\nEnter Peer's Test Onion Address: ").strip()
        peer_pubkey = input("Enter Peer's Test PubKey (Hex): ").strip()
    except KeyboardInterrupt:
        running = False
        return

    if not peer_onion.endswith(".onion") or len(peer_pubkey) != 64:
        print_log("[FATAL] Invalid peer credentials input. Exiting.")
        running = False
        return

    # Add peer to temporary contacts db
    db.put("contacts", peer_onion, {
        "name": "PeerAgent",
        "pubkey": peer_pubkey
    })

    print_log(f"Starting automated outbound loop to {peer_onion}...")
    proxy = tor.get_socks_proxy()
    socks_host, socks_port = proxy if proxy else ("127.0.0.1", 9050)

    # Outbound dial loop
    attempts = 0
    while running and not (sent_success and received_success):
        if not sent_success:
            attempts += 1
            print_log(f"Outbound dial attempt #{attempts} to {peer_onion}:80 via SOCKS5...")
            try:
                # Load or initialize ratchet session
                ratchet = session_mgr.get_session(peer_onion)
                if not ratchet:
                    print_log("Initializing Alice ratchet session for peer...")
                    ratchet = session_mgr.initialize_alice_session(peer_onion, peer_pubkey)
                
                # Encrypt E2EE diagnostic payload
                msg_text = f"Cooperative check SUCCESS! Greeting from Antigravity agent. Attempt: {attempts}"
                dh_pub, ciphertext, pn, n_s = ratchet.ratchet_encrypt(msg_text.encode('utf-8'))
                session_mgr.save_session(peer_onion, ratchet)
                
                header = {
                    "dh_pub": dh_pub,
                    "pn": pn,
                    "n": n_s,
                    "sender_onion": onion,
                    "sender_pubkey": vk_bytes
                }
                
                frame_bytes = encrypt_and_pack_frame(header, ciphertext)
                
                # Connect to peer
                sock = socks5_connect(socks_host, socks_port, peer_onion, 80)
                sock.sendall(frame_bytes)
                sock.close()
                
                print_log("[+] Outbox E2EE frame transmitted successfully!")
                sent_success = True
            except Exception as e:
                print_log(f"[-] Outbox connection failed (yet): {e}")
                print_log("    Waiting 10 seconds before retrying...")

        if not (sent_success and received_success):
            time.sleep(10.0)

    # Clean termination
    running = False
    print("\n" + "#"*70)
    print("      [ALL SYSTEMS GO] P2P E2EE NETWORKING SECURELY VERIFIED!")
    print("      Both sending and receiving chains are fully functional.")
    print("#"*70 + "\n")
    
    tor.close()
    print_log("Diagnostic tool closed successfully.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        running = False
        print("\nAborted.")
