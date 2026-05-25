import os
import re
import urllib.request
import tarfile
from pathlib import Path
from PySide6.QtCore import QThread, Signal

class TorDownloaderThread(QThread):
    progress = Signal(int)
    log = Signal(str)
    finished = Signal(bool, str) # success, message
    
    def __init__(self, bin_dir: str):
        super().__init__()
        self.bin_dir = Path(bin_dir)
        
    def run(self):
        try:
            self.log.emit("Locating latest Tor version...")
            req = urllib.request.Request(
                'https://dist.torproject.org/torbrowser/', 
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            html = urllib.request.urlopen(req, timeout=10).read().decode()
            versions = re.findall(r'<a href="([0-9\.]+)/">', html)
            if not versions:
                raise Exception("Could not find any Tor versions on dist.torproject.org")
                
            latest_version = sorted(versions, key=lambda x: [int(p) for p in x.split('.')])[-1]
            
            self.log.emit(f"Found latest version: {latest_version}")
            
            url = f"https://dist.torproject.org/torbrowser/{latest_version}/tor-expert-bundle-windows-x86_64-{latest_version}.tar.gz"
            self.log.emit(f"Downloading Tor v{latest_version}...")
            
            self.bin_dir.mkdir(parents=True, exist_ok=True)
            tar_path = self.bin_dir / "tor.tar.gz"
            
            def reporthook(blocknum, blocksize, totalsize):
                readsofar = blocknum * blocksize
                if totalsize > 0:
                    percent = int((readsofar * 100) / totalsize)
                    self.progress.emit(min(percent, 100))
                    
            req_dl = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req_dl, timeout=30) as response, open(tar_path, 'wb') as out_file:
                totalsize = int(response.info().get("Content-Length", 0))
                readsofar = 0
                blocksize = 8192
                while True:
                    buffer = response.read(blocksize)
                    if not buffer:
                        break
                    out_file.write(buffer)
                    readsofar += len(buffer)
                    if totalsize > 0:
                        percent = int((readsofar * 100) / totalsize)
                        self.progress.emit(min(percent, 100))
            
            self.log.emit("Extracting Tor binaries...")
            with tarfile.open(tar_path, "r:gz") as tar:
                # Expert bundle extracts into "tor/" directory
                tar.extractall(path=self.bin_dir)
                
            # Cleanup
            if tar_path.exists():
                tar_path.unlink()
            
            self.log.emit("Download complete.")
            self.finished.emit(True, "Tor Expert Bundle installed successfully.")
        except Exception as e:
            self.finished.emit(False, str(e))
