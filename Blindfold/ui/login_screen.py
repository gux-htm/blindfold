from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPixmap
import os
from core.identity import unlock_or_create_vault

from PySide6.QtCore import QThread

class UnlockThread(QThread):
    finished = Signal(bytes, bytes)
    error = Signal(str)
    
    def __init__(self, pwd):
        super().__init__()
        self.pwd = pwd
        
    def run(self):
        try:
            master_key, pubkey = unlock_or_create_vault(self.pwd)
            self.finished.emit(master_key, pubkey)
        except Exception as e:
            self.error.emit(str(e))

class LoginScreen(QWidget):
    login_successful = Signal(bytes, bytes)

    def __init__(self):
        super().__init__()
        self.unlock_thread = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        
        # Load user's logo.jfif
        self.logo_label = QLabel()
        pixmap = QPixmap(os.path.join(os.path.dirname(__file__), "..", "..", "logo.jfif")) 
        if not pixmap.isNull():
            self.logo_label.setPixmap(pixmap.scaledToWidth(300, Qt.SmoothTransformation))
        else:
            pixmap = QPixmap("logo.jfif")
            if not pixmap.isNull():
                self.logo_label.setPixmap(pixmap.scaledToWidth(300, Qt.SmoothTransformation))
                
        layout.addWidget(self.logo_label, alignment=Qt.AlignCenter)
        
        title = QLabel("B L I N D F O L D")
        title.setStyleSheet("color: #7D4698; font-size: 36px; font-weight: bold; font-family: 'Courier New'; letter-spacing: 5px;")
        layout.addWidget(title, alignment=Qt.AlignCenter)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter Vault Passphrase...")
        self.password_input.setMinimumWidth(350)
        self.password_input.setStyleSheet("""
            QLineEdit {
                background-color: #14161A;
                border: 2px solid #2D3139;
                color: #FFFFFF;
                padding: 12px;
                font-family: 'Courier New';
                font-size: 16px;
            }
            QLineEdit:focus {
                border: 2px solid #7D4698;
            }
        """)
        layout.addWidget(self.password_input, alignment=Qt.AlignCenter)
        
        self.login_btn = QPushButton("UNLOCK VAULT")
        self.login_btn.setMinimumWidth(350)
        self.login_btn.setStyleSheet("""
            QPushButton {
                background-color: #7D4698;
                border: none;
                color: #FFFFFF;
                padding: 15px;
                font-family: 'Courier New';
                font-weight: bold;
                font-size: 18px;
                margin-top: 20px;
            }
            QPushButton:hover {
                background-color: #8C53A8;
            }
            QPushButton:disabled {
                background-color: #2D3139;
                color: #4A505C;
            }
        """)
        self.login_btn.clicked.connect(self.on_login)
        self.password_input.returnPressed.connect(self.on_login)
        layout.addWidget(self.login_btn, alignment=Qt.AlignCenter)

    def on_login(self):
        pwd = self.password_input.text()
        if len(pwd) < 4:
            QMessageBox.warning(self, "Error", "Passphrase too short.")
            return
            
        self.login_btn.setText("DERIVING KEY...")
        self.login_btn.setEnabled(False)
        self.password_input.setEnabled(False)
        
        self.unlock_thread = UnlockThread(pwd)
        self.unlock_thread.finished.connect(self.on_unlock_success)
        self.unlock_thread.error.connect(self.on_unlock_error)
        self.unlock_thread.start()
        
    def on_unlock_success(self, master_key, pubkey):
        self.login_successful.emit(master_key, pubkey)
        
    def on_unlock_error(self, err_msg):
        QMessageBox.critical(self, "Error", f"Failed to unlock vault: {err_msg}")
        self.login_btn.setText("UNLOCK VAULT")
        self.login_btn.setEnabled(True)
        self.password_input.setEnabled(True)
