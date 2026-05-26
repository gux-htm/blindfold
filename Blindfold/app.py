import sys
import logging
from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow

def main():
    # Configure logging to stdout
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    
    app = QApplication(sys.argv)
    
    # Initialize DI Container / Core Services here later
    # e.g., identity_store, ratchet_engine, network_client
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
