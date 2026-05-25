import random
import asyncio
import os
from typing import Optional

BLOCK_SIZE = 512

class TrafficShaper:
    """
    Implements traffic analysis resistance techniques:
    1. Payload padding (to multiples of 512 bytes)
    2. Random transmission jitter (+/- 200ms)
    """
    def __init__(self, max_jitter_ms: int = 200, enable_cover_traffic: bool = False):
        self.max_jitter_ms = max_jitter_ms
        self.enable_cover_traffic = enable_cover_traffic
        
    def pad_payload(self, payload: bytes) -> bytes:
        """Pad payload to a multiple of BLOCK_SIZE. Uses PKCS#7-like padding but randomized."""
        pad_len = BLOCK_SIZE - (len(payload) % BLOCK_SIZE)
        if pad_len == 0:
            pad_len = BLOCK_SIZE
        # Fill padding with random bytes, last byte is the length of the padding
        padding = os.urandom(pad_len - 1) + bytes([pad_len])
        return payload + padding
        
    def unpad_payload(self, padded_payload: bytes) -> bytes:
        """Remove padding from the payload."""
        if not padded_payload:
            return padded_payload
        pad_len = padded_payload[-1]
        if pad_len > BLOCK_SIZE or pad_len == 0 or pad_len > len(padded_payload):
            # Invalid padding length
            return padded_payload
        return padded_payload[:-pad_len]

    async def apply_jitter(self):
        """Sleep for a random duration up to max_jitter_ms."""
        if self.max_jitter_ms > 0:
            delay = random.uniform(0, self.max_jitter_ms) / 1000.0
            await asyncio.sleep(delay)

    async def cover_traffic_loop(self, connection):
        """Background task to inject dummy packets when idle."""
        while self.enable_cover_traffic:
            # Wait a random interval between 5 and 15 seconds
            await asyncio.sleep(random.uniform(5.0, 15.0))
            # In a full implementation, we would inject a dummy frame here 
            # with a special flag indicating it's cover traffic.
