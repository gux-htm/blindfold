import time
import uuid
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                               QListWidget, QListWidgetItem, QInputDialog, QMessageBox, 
                               QLabel, QTextEdit, QLineEdit, QSplitter, QDialog, QFormLayout, QDialogButtonBox)
from PySide6.QtCore import Qt, Signal

class AddContactDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Secure Contact")
        self.setStyleSheet("""
            QDialog { background-color: #0A0A0C; border: 2px solid #2D3139; }
            QLabel { color: #A0A5B5; font-family: 'Courier New'; font-size: 14px; }
            QLineEdit { background-color: #14161A; border: 1px solid #2D3139; color: #FFFFFF; padding: 5px; font-family: 'Courier New'; }
            QPushButton { background-color: #1E2128; border: 1px solid #2D3139; color: #7D4698; padding: 5px 15px; font-family: 'Courier New'; }
            QPushButton:hover { background-color: #2D3139; color: #FFFFFF; }
        """)
        
        layout = QFormLayout(self)
        self.name_input = QLineEdit()
        self.onion_input = QLineEdit()
        self.pubkey_input = QLineEdit()
        
        layout.addRow("Contact Name:", self.name_input)
        layout.addRow("Onion Address:", self.onion_input)
        layout.addRow("Public Key (Hex):", self.pubkey_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        
    def get_data(self):
        return self.name_input.text(), self.onion_input.text(), self.pubkey_input.text()

class ChatTab(QWidget):
    send_message_signal = Signal(str, str) # onion_address, message

    def __init__(self, db, my_onion: str, my_pubkey_hex: str):
        super().__init__()
        self.db = db
        self.my_onion = my_onion
        self.my_pubkey_hex = my_pubkey_hex
        self.current_contact_onion = None
        
        self._setup_ui()
        self.refresh_contacts()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # --- Top Identity Bar ---
        top_bar = QHBoxLayout()
        identity_label = QLabel("My Identity:")
        identity_label.setStyleSheet("color: #7D4698; font-weight: bold; font-family: 'Courier New'; font-size: 14px;")
        
        self.onion_display = QLineEdit(self.my_onion)
        self.onion_display.setReadOnly(True)
        self.onion_display.setStyleSheet("background: #0A0A0C; border: 1px solid #2D3139; color: #A0A5B5; font-family: 'Courier New';")
        
        self.pubkey_display = QLineEdit(self.my_pubkey_hex)
        self.pubkey_display.setReadOnly(True)
        self.pubkey_display.setStyleSheet("background: #0A0A0C; border: 1px solid #2D3139; color: #A0A5B5; font-family: 'Courier New';")
        
        top_bar.addWidget(identity_label)
        top_bar.addWidget(QLabel(" Onion:"))
        top_bar.addWidget(self.onion_display)
        top_bar.addWidget(QLabel(" PubKey:"))
        top_bar.addWidget(self.pubkey_display)
        main_layout.addLayout(top_bar)
        
        # --- Splitter (Contacts Left, Chat Right) ---
        splitter = QSplitter(Qt.Horizontal)
        
        # Left Panel (Contacts)
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        self.contact_list = QListWidget()
        self.contact_list.setStyleSheet("""
            QListWidget { background-color: #14161A; border: 2px solid #2D3139; color: #FFFFFF; font-family: 'Courier New'; font-size: 14px; }
            QListWidget::item { padding: 10px; border-bottom: 1px solid #2D3139; }
            QListWidget::item:selected { background-color: #2D3139; color: #7D4698; border-left: 4px solid #7D4698; }
        """)
        self.contact_list.itemClicked.connect(self.on_contact_selected)
        
        self.btn_add_contact = QPushButton("+ Add Contact")
        self.btn_add_contact.setStyleSheet("""
            QPushButton { background-color: #1E2128; border: 2px solid #2D3139; color: #7D4698; padding: 10px; font-family: 'Courier New'; font-weight: bold; }
            QPushButton:hover { background-color: #2D3139; color: #FFFFFF; }
        """)
        self.btn_add_contact.clicked.connect(self.on_add_contact)
        
        left_layout.addWidget(self.contact_list)
        left_layout.addWidget(self.btn_add_contact)
        
        # Right Panel (Chat)
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_history.setStyleSheet("""
            QTextEdit { background-color: #0A0A0C; border: 2px solid #2D3139; color: #A0A5B5; font-family: 'Courier New'; font-size: 14px; padding: 10px; }
        """)
        
        input_layout = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setStyleSheet("""
            QLineEdit { background-color: #14161A; border: 2px solid #2D3139; color: #FFFFFF; padding: 10px; font-family: 'Courier New'; font-size: 14px; }
            QLineEdit:focus { border: 2px solid #7D4698; }
        """)
        self.chat_input.returnPressed.connect(self.on_send_message)
        
        self.btn_send = QPushButton("SEND")
        self.btn_send.setStyleSheet("""
            QPushButton { background-color: #7D4698; border: none; color: #FFFFFF; padding: 10px 20px; font-family: 'Courier New'; font-weight: bold; }
            QPushButton:hover { background-color: #8C53A8; }
        """)
        self.btn_send.clicked.connect(self.on_send_message)
        
        input_layout.addWidget(self.chat_input)
        input_layout.addWidget(self.btn_send)
        
        right_layout.addWidget(self.chat_history)
        right_layout.addLayout(input_layout)
        
        # Assemble Splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([200, 600])
        
        main_layout.addWidget(splitter)

    def refresh_contacts(self):
        self.contact_list.clear()
        contacts = self.db.get_all("contacts")
        for onion, meta in contacts.items():
            item = QListWidgetItem(meta['name'])
            item.setData(Qt.UserRole, onion)
            self.contact_list.addItem(item)

    def on_add_contact(self):
        dialog = AddContactDialog(self)
        if dialog.exec():
            name, onion, pubkey = dialog.get_data()
            if not name or not onion or not pubkey:
                QMessageBox.warning(self, "Error", "All fields are required.")
                return
            
            if not onion.endswith(".onion"):
                QMessageBox.warning(self, "Error", "Invalid Onion address.")
                return
                
            self.db.put("contacts", onion, {"name": name, "pubkey": pubkey})
            self.refresh_contacts()

    def on_contact_selected(self, item):
        self.current_contact_onion = item.data(Qt.UserRole)
        self.refresh_chat_history()
        
    def refresh_chat_history(self):
        self.chat_history.clear()
        if not self.current_contact_onion:
            return
            
        messages = self.db.get_all(f"msgs_{self.current_contact_onion}")
        # Sort by timestamp
        sorted_msgs = sorted(messages.values(), key=lambda x: x['timestamp'])
        
        for msg in sorted_msgs:
            sender = "Me" if msg['sender'] == "me" else self.db.get("contacts", self.current_contact_onion).get('name', 'Them')
            color = "#7D4698" if msg['sender'] == "me" else "#00FF9F"
            
            # Format: [Time] Sender: Message
            time_str = time.strftime('%H:%M:%S', time.localtime(msg['timestamp']))
            html = f'<span style="color: #4A505C;">[{time_str}]</span> <strong style="color: {color};">{sender}:</strong> <span style="color: #FFFFFF;">{msg["content"]}</span>'
            self.chat_history.append(html)

    def on_send_message(self):
        if not self.current_contact_onion:
            QMessageBox.warning(self, "Error", "Select a contact first.")
            return
            
        text = self.chat_input.text().strip()
        if not text:
            return
            
        self.chat_input.clear()
        
        # Save to DB
        msg_id = str(uuid.uuid4())
        msg_data = {
            "sender": "me",
            "timestamp": time.time(),
            "content": text
        }
        self.db.put(f"msgs_{self.current_contact_onion}", msg_id, msg_data)
        self.refresh_chat_history()
        
        # Signal backend to route it via Tor & Ratchet
        self.send_message_signal.emit(self.current_contact_onion, text)

    def receive_message(self, onion_address: str, text: str):
        """Called by the backend when a message is received over Tor."""
        msg_id = str(uuid.uuid4())
        msg_data = {
            "sender": "them",
            "timestamp": time.time(),
            "content": text
        }
        self.db.put(f"msgs_{onion_address}", msg_id, msg_data)
        
        if self.current_contact_onion == onion_address:
            self.refresh_chat_history()
