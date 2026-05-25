import os
import uuid
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                               QListWidget, QListWidgetItem, QFileDialog, QMessageBox, QLabel)
from PySide6.QtGui import QIcon, QPixmap, QPainter
from PySide6.QtCore import Qt, QByteArray
from PySide6.QtSvg import QSvgRenderer
from ui.icons import LOCK_ICON_SVG
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class VaultTab(QWidget):
    def __init__(self, kms, encryptor, shredder, db):
        super().__init__()
        self.kms = kms
        self.encryptor = encryptor
        self.shredder = shredder
        self.db = db
        self._setup_ui()
        self.refresh_list()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Secure File Vault")
        header.setStyleSheet("color: #7D4698; font-size: 20px; font-weight: bold; font-family: 'Courier New';")
        layout.addWidget(header)
        
        self.list_widget = QListWidget()
        self.list_widget.setStyleSheet("""
            QListWidget {
                background-color: #14161A;
                border: 2px solid #2D3139;
                color: #A0A5B5;
                font-family: 'Courier New';
                padding: 10px;
                font-size: 16px;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #2D3139;
            }
            QListWidget::item:selected {
                background-color: #2D3139;
                color: #FFFFFF;
                border-left: 4px solid #7D4698;
            }
        """)
        layout.addWidget(self.list_widget)
        
        btn_layout = QHBoxLayout()
        self.btn_add = QPushButton("Encrypt File")
        self.btn_decrypt = QPushButton("Decrypt File")
        self.btn_shred = QPushButton("Shred File")
        
        for btn in (self.btn_add, self.btn_decrypt, self.btn_shred):
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #1E2128;
                    border: 2px solid #2D3139;
                    color: #7D4698;
                    padding: 10px;
                    font-family: 'Courier New';
                    font-weight: bold;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #2D3139;
                    color: #FFFFFF;
                    border-color: #7D4698;
                }
            """)
            btn_layout.addWidget(btn)
            
        layout.addLayout(btn_layout)
        
        self.btn_add.clicked.connect(self.on_add_file)
        self.btn_decrypt.clicked.connect(self.on_decrypt)
        self.btn_shred.clicked.connect(self.on_shred)

    def _get_svg_icon(self, svg_str):
        # Render SVG to QPixmap
        renderer = QSvgRenderer(QByteArray(svg_str.encode('utf-8')))
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        renderer.render(painter)
        painter.end()
        return QIcon(pixmap)

    def refresh_list(self):
        self.list_widget.clear()
        files = self.db.get_all("files")
        
        icon = self._get_svg_icon(LOCK_ICON_SVG)
        
        for file_id, meta in files.items():
            item = QListWidgetItem(icon, "  " + meta['name'])
            item.setData(Qt.UserRole, file_id)
            self.list_widget.addItem(item)

    def on_add_file(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if not filepath:
            return
            
        file_id = str(uuid.uuid4())
        filename = os.path.basename(filepath)
        out_path = filepath + ".bf"
        
        try:
            fek = self.kms.generate_and_wrap_file_key(file_id)
            self.encryptor.aesgcm = AESGCM(fek)
            self.encryptor.encrypt_file(filepath, out_path)
            
            # Shred original
            self.shredder.shred_file(filepath)
            
            # Store metadata
            self.db.put("files", file_id, {"name": filename, "path": out_path})
            self.refresh_list()
            QMessageBox.information(self, "Success", f"File encrypted and original shredded:\n{filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to encrypt: {e}")

    def on_decrypt(self):
        item = self.list_widget.currentItem()
        if not item:
            QMessageBox.warning(self, "Selection", "Please select a file to decrypt.")
            return
            
        file_id = item.data(Qt.UserRole)
        meta = self.db.get("files", file_id)
        if not meta:
            return
            
        enc_path = meta['path']
        if not os.path.exists(enc_path):
            QMessageBox.warning(self, "Missing", "Encrypted file not found on disk.")
            return
            
        out_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File As", meta['name'])
        if not out_path:
            return
            
        try:
            fek = self.kms.unwrap_file_key(file_id)
            if not fek:
                raise ValueError("Key not found in KMS")
                
            self.encryptor.aesgcm = AESGCM(fek)
            self.encryptor.decrypt_file(enc_path, out_path)
            
            QMessageBox.information(self, "Success", f"File decrypted successfully:\n{out_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to decrypt: {e}")

    def on_shred(self):
        item = self.list_widget.currentItem()
        if not item:
            QMessageBox.warning(self, "Selection", "Please select a file to shred.")
            return
            
        reply = QMessageBox.question(self, "Confirm Shred", 
            "This will securely and permanently destroy the encrypted file and its key. Are you sure?",
            QMessageBox.Yes | QMessageBox.No)
            
        if reply == QMessageBox.Yes:
            file_id = item.data(Qt.UserRole)
            meta = self.db.get("files", file_id)
            if meta and os.path.exists(meta['path']):
                self.shredder.shred_file(meta['path'])
            self.kms.shred_file_key(file_id)
            self.db.delete("files", file_id)
            self.refresh_list()
