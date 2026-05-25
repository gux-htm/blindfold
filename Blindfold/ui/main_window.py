from PySide6.QtWidgets import QMainWindow, QStackedWidget, QTabWidget, QWidget, QVBoxLayout, QLabel, QMessageBox
from PySide6.QtCore import Qt, QThread, Signal
import os

from ui.login_screen import LoginScreen
from ui.vault_tab import VaultTab
from ui.chat_tab import ChatTab
from storage.db import EncryptedDatabase
from files.vault import VaultKMS
from files.encryptor import FileEncryptor
from files.shredder import SecureShredder
from anonymity.tor_manager import TorManager
from anonymity.tor_downloader import TorDownloaderThread

class TorSetupThread(QThread):
    finished = Signal(str)
    download_progress = Signal(int)
    download_log = Signal(str)
    
    def run(self):
        tor = TorManager()
        if not tor.connect():
            self.download_log.emit("Tor not found. Starting download...")
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            bin_dir = os.path.join(project_root, "bin")
            
            downloader = TorDownloaderThread(bin_dir)
            downloader.progress.connect(self.download_progress.emit)
            downloader.log.connect(self.download_log.emit)
            
            # Run synchronously inside this background thread
            downloader.run()
            
            if not tor.connect():
                self.finished.emit("Failed to download or connect to embedded Tor.")
                return

        self.download_log.emit("Creating Tor Hidden Service...")
        onion = tor.create_ephemeral_hidden_service(8080)
        if onion:
            self.finished.emit(onion)
        else:
            self.finished.emit("Failed to create Hidden Service")

class MainDashboard(QWidget):
    def __init__(self, master_key: bytes, pubkey: bytes):
        super().__init__()
        self.master_key = master_key
        self.pubkey = pubkey
        self.onion_address = "Waiting for Tor..."
        self._init_backend()
        self._setup_ui()

    def _init_backend(self):
        # Initialize the secure backend
        self.db = EncryptedDatabase(self.master_key)
        self.kms = VaultKMS(self.master_key, self.db)
        self.encryptor = FileEncryptor(self.master_key) 
        self.shredder = SecureShredder()
        
        # Initialize Tor asynchronously
        self.tor_thread = TorSetupThread()
        self.tor_thread.finished.connect(self.on_tor_ready)
        self.tor_thread.download_log.connect(self.on_tor_log)
        self.tor_thread.download_progress.connect(self.on_tor_progress)
        self.tor_thread.start()

    def on_tor_log(self, msg: str):
        self.onion_address = msg
        if hasattr(self, 'chat_tab'):
            self.chat_tab.onion_display.setText(msg)

    def on_tor_progress(self, percent: int):
        msg = f"Downloading Tor... {percent}%"
        self.onion_address = msg
        if hasattr(self, 'chat_tab'):
            self.chat_tab.onion_display.setText(msg)

    def on_tor_ready(self, onion_address):
        self.onion_address = onion_address
        if hasattr(self, 'chat_tab'):
            self.chat_tab.onion_display.setText(onion_address)

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #2D3139;
                background: #000000;
            }
            QTabBar::tab {
                background: #14161A;
                color: #A0A5B5;
                padding: 10px 20px;
                font-family: 'Courier New';
                font-size: 16px;
                border: 1px solid #2D3139;
                border-bottom: none;
            }
            QTabBar::tab:selected {
                background: #1E2128;
                color: #7D4698;
                border-top: 2px solid #7D4698;
            }
        """)
        
        # Chat Tab
        self.chat_tab = ChatTab(self.db, self.onion_address, self.pubkey.hex())
        
        # Vault Tab
        self.vault_tab = VaultTab(self.kms, self.encryptor, self.shredder, self.db)
        
        self.tabs.addTab(self.chat_tab, "Anonymous Chat")
        self.tabs.addTab(self.vault_tab, "File Vault")
        
        layout.addWidget(self.tabs)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Blindfold Sovereign Communications")
        self.setMinimumSize(900, 600)
        
        # Deep Black / Tor Purple Aesthetic
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
            }
        """)
        
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)
        
        self.login_screen = LoginScreen()
        self.login_screen.login_successful.connect(self.on_login_successful)
        
        self.stacked_widget.addWidget(self.login_screen)

    def on_login_successful(self, master_key: bytes, pubkey: bytes):
        self.dashboard = MainDashboard(master_key, pubkey)
        self.stacked_widget.addWidget(self.dashboard)
        self.stacked_widget.setCurrentWidget(self.dashboard)

