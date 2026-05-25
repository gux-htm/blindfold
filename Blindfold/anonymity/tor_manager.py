import logging
import os
from pathlib import Path
from typing import Optional, Tuple
from stem.control import Controller
from stem import SocketError
import stem.process

logger = logging.getLogger(__name__)

# Common Tor control and SOCKS ports
TOR_PORTS = [
    {"control": 9151, "socks": 9150, "desc": "Tor Browser"},
    {"control": 9051, "socks": 9050, "desc": "System Tor"},
]

class TorManager:
    def __init__(self):
        self.controller: Optional[Controller] = None
        self.tor_process = None
        self.socks_port: Optional[int] = None
        self.control_port: Optional[int] = None
        self.active_onion: Optional[str] = None

    def launch_embedded_tor(self) -> bool:
        """Launch the embedded Tor binary if available."""
        project_root = Path(__file__).parent.parent
        tor_path = project_root / "bin" / "tor" / "tor.exe"
        
        if not tor_path.exists():
            return False
            
        data_dir = Path("~/.blindfold/tor_data").expanduser()
        data_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Launching embedded Tor from {tor_path}...")
        try:
            self.tor_process = stem.process.launch_tor_with_config(
                config={
                    'SocksPort': '9050',
                    'ControlPort': '9051',
                    'DataDirectory': str(data_dir),
                },
                tor_cmd=str(tor_path),
                take_ownership=True,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to launch embedded Tor: {e}")
            return False

    def connect(self) -> bool:
        """Attempt to connect to a running Tor instance, or launch the embedded one."""
        # Try connecting to existing Tor first
        for port_config in TOR_PORTS:
            try:
                c = Controller.from_port(port=port_config["control"])
                c.authenticate() 
                self.controller = c
                self.control_port = port_config["control"]
                self.socks_port = port_config["socks"]
                logger.info(f"Connected to {port_config['desc']} on control port {self.control_port}")
                return True
            except SocketError:
                continue
            except Exception as e:
                logger.warning(f"Failed to authenticate to Tor on {port_config['control']}: {e}")
                continue

        # If not connected, try launching embedded
        if self.launch_embedded_tor():
            # Try connecting again after launching
            for port_config in TOR_PORTS:
                try:
                    c = Controller.from_port(port=port_config["control"])
                    c.authenticate()
                    self.controller = c
                    self.control_port = port_config["control"]
                    self.socks_port = port_config["socks"]
                    logger.info(f"Connected to Embedded Tor on control port {self.control_port}")
                    return True
                except Exception:
                    continue

        logger.error("Could not connect to any Tor instance, and embedded Tor is missing.")
        return False

    def create_ephemeral_hidden_service(self, target_port: int) -> Optional[str]:
        """Create a v3 ephemeral hidden service pointing to the local target_port."""
        if not self.controller:
            if not self.connect():
                return None
                
        try:
            # Create a v3 hidden service that points to our local server port
            response = self.controller.create_ephemeral_hidden_service(
                {80: target_port}, 
                await_publication=False,
                key_type="NEW", 
                key_content="ED25519-V3"
            )
            self.active_onion = f"{response.service_id}.onion"
            logger.info(f"Created ephemeral hidden service: {self.active_onion}")
            return self.active_onion
        except Exception as e:
            logger.error(f"Failed to create hidden service: {e}")
            return None

    def stop_hidden_service(self):
        """Stop the ephemeral hidden service."""
        if self.controller and self.active_onion:
            service_id = self.active_onion.replace(".onion", "")
            try:
                self.controller.remove_ephemeral_hidden_service(service_id)
                self.active_onion = None
                logger.info("Hidden service stopped.")
            except Exception as e:
                logger.error(f"Failed to stop hidden service: {e}")

    def get_socks_proxy(self) -> Optional[Tuple[str, int]]:
        """Return the (host, port) for the active Tor SOCKS proxy."""
        if not self.socks_port:
            if not self.connect():
                return None
        return ("127.0.0.1", self.socks_port)

    def close(self):
        if self.controller:
            self.stop_hidden_service()
            self.controller.close()
            self.controller = None
