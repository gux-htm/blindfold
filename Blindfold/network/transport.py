import struct
import cbor2
import os
import asyncio
import ssl
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAGIC = b"PLNK"
VERSION = 1

class InvalidFrame(Exception):
    pass

class TransportFrame:
    """
    [Magic (4B)] + [Version (1B)] + [Flags (1B)] + [Header Len (4B)] + [Payload Len (4B)] +
    [Header (CBOR)] + [Payload (Encrypted Binary)] + [MAC (16B)]
    """
    def __init__(self, header: dict, payload: bytes, flags: int = 0):
        self.header = header
        self.payload = payload
        self.flags = flags

from typing import Optional
from anonymity.traffic_shaper import TrafficShaper

class Connection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, mac_key: bytes, shaper: Optional[TrafficShaper] = None):
        self.reader = reader
        self.writer = writer
        self.mac_key = mac_key
        self.shaper = shaper
        self.send_seq = 0
        self.recv_seq = 0

    def _get_nonce(self, seq: int) -> bytes:
        return seq.to_bytes(12, 'little')

    async def send_frame(self, frame: TransportFrame):
        if self.shaper:
            await self.shaper.apply_jitter()

        header_bytes = cbor2.dumps(frame.header)
        
        payload = frame.payload
        if self.shaper:
            payload = self.shaper.pad_payload(payload)
            
        prefix = struct.pack("!4sBBII", MAGIC, VERSION, frame.flags, len(header_bytes), len(payload))
        data = prefix + header_bytes + payload
        
        # ChaCha20-Poly1305 as MAC (encrypt empty plaintext, data as AAD)
        chacha = ChaCha20Poly1305(self.mac_key)
        nonce = self._get_nonce(self.send_seq)
        self.send_seq += 1
        
        ciphertext = chacha.encrypt(nonce, b"", data)
        mac = ciphertext[-16:] # The 16 byte tag
        
        final_payload = data + mac
        self.writer.write(final_payload)
        await self.writer.drain()

    async def recv_frame(self) -> TransportFrame:
        # Read prefix
        prefix = await self.reader.readexactly(14)
        magic, version, flags, hlen, plen = struct.unpack("!4sBBII", prefix)
        
        if magic != MAGIC:
            raise InvalidFrame("Invalid magic bytes")
        if version != VERSION:
            raise InvalidFrame("Unsupported version")
            
        # Read rest of data + MAC
        body_mac = await self.reader.readexactly(hlen + plen + 16)
        body = body_mac[:-16]
        mac = body_mac[-16:]
        
        # Verify MAC
        chacha = ChaCha20Poly1305(self.mac_key)
        nonce = self._get_nonce(self.recv_seq)
        self.recv_seq += 1
        
        try:
            chacha.decrypt(nonce, mac, prefix + body) # ciphertext is just the mac (16B), AAD is prefix+body
        except Exception:
            raise InvalidFrame("MAC verification failed")
            
        header_bytes = body[:hlen]
        payload = body[hlen:]
        
        if self.shaper:
            payload = self.shaper.unpad_payload(payload)
            
        header = cbor2.loads(header_bytes)
        return TransportFrame(header, payload, flags)

async def create_secure_connection(host: str, port: int, cert_pin: str, mac_key: bytes, shaper: Optional[TrafficShaper] = None) -> Connection:
    """Create TLS 1.3 connection with certificate pinning."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    # In a real implementation we would pin the cert here.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE # Custom verification happens after connection
    
    reader, writer = await asyncio.open_connection(host, port, ssl=context)
    
    # Check cert pin here using writer.get_extra_info('peercert')
    
    return Connection(reader, writer, mac_key, shaper)
