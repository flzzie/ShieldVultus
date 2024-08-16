import sys
import os
import shutil
import requests
import logging
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
                             QLineEdit, QTextEdit, QFileDialog, QTabWidget, QListWidget)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

# Logging Configuration
logging.basicConfig(filename='antivirus.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AntivirusGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("🛡️ ShieldVultus")
        self.setGeometry(100, 100, 900, 700)
        self.setStyleSheet("background-color: #2f343f;")
        # Main widget and layout
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.layout = QVBoxLayout()
        self.main_widget.setLayout(self.layout)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3b3f54;  # Dark gray border
            }
            QTabBar::tab {
                background: #3b3f54;  # Dark gray
                color: #ffffff;
                font-size: 18pt;  # Increased font size
                padding: 14px 28px;  # Increased padding for better readability
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #4f5467;  # Slightly lighter gray
                color: #ffffff;
                font-weight: bold;
            }
        """)
        self.layout.addWidget(self.tabs)

        self.scan_tab = QWidget()
        self.url_tab = QWidget()
        self.quarantine_tab = QWidget()

        self.tabs.addTab(self.scan_tab, 'File Scan')
        self.tabs.addTab(self.url_tab, 'URL Check')
        self.tabs.addTab(self.quarantine_tab, 'Quarantine')

        self.init_scan_tab()
        self.init_url_tab()
        self.init_quarantine_tab()

        # Ensure quarantine directory exists
        self.quarantine_dir = "quarantine"
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

        # Set your VirusTotal API key here
        self.virustotal_api_key = '47238675c29017c7242b3dce09c514b8f46f7a79f0e3cf0faf886b00be3874fa'  # Replace with your VirusTotal API key

    def init_scan_tab(self):
        layout = QVBoxLayout()
        self.scan_tab.setLayout(layout)

        scan_layout = QHBoxLayout()
        layout.addLayout(scan_layout)

        self.scan_label = QLabel("Select a file or type a directory to scan:")
        self.scan_label.setFont(QFont('Arial', 16))  # Adjust font size
        self.scan_label.setStyleSheet("color: #ffffff;")  # Color of text
        scan_layout.addWidget(self.scan_label)

        self.scan_entry = QLineEdit()
        self.scan_entry.setFont(QFont('Arial', 16))  # 
        self.scan_entry.setMinimumWidth(500)  # Change width
        self.scan_entry.setStyleSheet("background-color: #4f5467; color: #ffffff; padding: 10px; border: 1px solid #3b3f54;")  # Adjusted padding
        scan_layout.addWidget(self.scan_entry)

        self.browse_button = QPushButton("Browse")
        self.browse_button.setFont(QFont('Arial', 14))  
        self.browse_button.setFixedSize(150, 50)  # Adjust button size
        self.browse_button.setStyleSheet("background-color: #87ceeb; color: #ffffff; padding: 5px; border: 1px solid #3b3f54;")
        self.browse_button.clicked.connect(self.browse_file_or_directory)
        scan_layout.addWidget(self.browse_button)

        self.scan_button = QPushButton("Scan")
        self.scan_button.setFont(QFont('Arial', 14))  
        self.scan_button.setFixedSize(150, 50)  
        self.scan_button.setStyleSheet("background-color: #e74c3c; color: #ffffff; padding: 5px; border: 1px solid #3b3f54;")
        self.scan_button.clicked.connect(self.scan_file_or_directory)
        scan_layout.addWidget(self.scan_button)

        self.result_label = QLabel("Scan Results:")
        self.result_label.setFont(QFont('Arial', 16)) 
        self.result_label.setStyleSheet("color: #ffffff;")
        layout.addWidget(self.result_label)

        self.result_text = QTextEdit()
        self.result_text.setFont(QFont('Arial', 16))  
        self.result_text.setMinimumHeight(300)  # Height
        self.result_text.setStyleSheet("background-color: #4f5467; color: #ffffff; padding: 10px; border: 1px solid #3b3f54;") 
        layout.addWidget(self.result_text)

    def init_url_tab(self):
        layout = QVBoxLayout()
        self.url_tab.setLayout(layout)

        url_layout = QHBoxLayout()
        layout.addLayout(url_layout)

        self.url_label = QLabel("Enter a URL to check:")
        self.url_label.setFont(QFont('Arial', 16))  # Larger font size
        self.url_label.setStyleSheet("color: #ffffff;")  # White text
        url_layout.addWidget(self.url_label)

        self.url_entry = QLineEdit()
        self.url_entry.setFont(QFont('Arial', 16))  # Larger font size
        self.url_entry.setMinimumWidth(500)  # Increased width
        self.url_entry.setStyleSheet("background-color: #4f5467; color: #ffffff; padding: 10px; border: 1px solid #3b3f54;")  # Adjusted padding
        url_layout.addWidget(self.url_entry)

        self.check_url_button = QPushButton("Check URL")
        self.check_url_button.setFont(QFont('Arial', 14))  # Larger font size
        self.check_url_button.setFixedSize(150, 50)  # Larger button size
        self.check_url_button.setStyleSheet("background-color: #2ecc71; color: #ffffff; padding: 5px; border: 1px solid #3b3f54;")
        self.check_url_button.clicked.connect(self.check_url)
        url_layout.addWidget(self.check_url_button)

        self.result_label_url = QLabel("URL Check Results:")
        self.result_label_url.setFont(QFont('Arial', 16))  # Larger font size
        self.result_label_url.setStyleSheet("color: #ffffff;")  # White text
        layout.addWidget(self.result_label_url)

        self.result_text_url = QTextEdit()
        self.result_text_url.setFont(QFont('Arial', 16))  # Larger font size
        self.result_text_url.setMinimumHeight(300)  # Increased height
        self.result_text_url.setStyleSheet("background-color: #4f5467; color: #ffffff; padding: 10px; border: 1px solid #3b3f54;")  # Adjusted padding
        layout.addWidget(self.result_text_url)

    def init_quarantine_tab(self):
        layout = QVBoxLayout()
        self.quarantine_tab.setLayout(layout)

        quarantine_layout = QHBoxLayout()
        layout.addLayout(quarantine_layout)

        self.quarantine_label = QLabel("Select a file to quarantine:")
        self.quarantine_label.setFont(QFont('Arial', 16))  # Larger font size
        self.quarantine_label.setStyleSheet("color: #ffffff;")  # White text
        quarantine_layout.addWidget(self.quarantine_label)

        self.quarantine_entry = QLineEdit()
        self.quarantine_entry.setFont(QFont('Arial', 16))  # Larger font size
        self.quarantine_entry.setMinimumWidth(500)  # Increased width
        self.quarantine_entry.setStyleSheet("background-color: #4f5467; color: #ffffff; padding: 10px; border: 1px solid #3b3f54;")  # Adjusted padding
        quarantine_layout.addWidget(self.quarantine_entry)

        self.browse_quarantine_button = QPushButton("Browse")
        self.browse_quarantine_button.setFont(QFont('Arial', 14))  # Larger font size
        self.browse_quarantine_button.setFixedSize(150, 50)  # Larger button size
        self.browse_quarantine_button.setStyleSheet("background-color: #87ceeb; color: #ffffff; padding: 5px; border: 1px solid #3b3f54;")
        self.browse_quarantine_button.clicked.connect(self.browse_file_for_quarantine)
        quarantine_layout.addWidget(self.browse_quarantine_button)

        self.quarantine_button = QPushButton("Quarantine")
        self.quarantine_button.setFont(QFont('Arial', 14))  # Larger font size
        self.quarantine_button.setFixedSize(150, 50)  # Larger button size
        self.quarantine_button.setStyleSheet("background-color: #e74c3c; color: #ffffff; padding: 5px; border: 1px solid #3b3f54;")
        self.quarantine_button.clicked.connect(self.quarantine_file)
        quarantine_layout.addWidget(self.quarantine_button)

        self.list_quarantine_button = QPushButton("List Quarantined Files")
        self.list_quarantine_button.setFont(QFont('Arial', 14))  # Larger font size
        self.list_quarantine_button.setFixedSize(200, 50)  # Larger button size
        self.list_quarantine_button.setStyleSheet("background-color: #87ceeb; color: #ffffff; padding: 5px; border: 1px solid #3b3f54;")
        self.list_quarantine_button.clicked.connect(self.list_quarantined_files)
        quarantine_layout.addWidget(self.list_quarantine_button)

        self.quarantine_result_label = QLabel("Quarantined Files:")
        self.quarantine_result_label.setFont(QFont('Arial', 16))  # Larger font size
        self.quarantine_result_label.setStyleSheet("color: #ffffff;")  # White text
        layout.addWidget(self.quarantine_result_label)

        self.quarantine_result_list = QListWidget()
        self.quarantine_result_list.setFont(QFont('Arial', 16))  # Larger font size
        self.quarantine_result_list.setMinimumHeight(300)  # Increased height
        self.quarantine_result_list.setStyleSheet("background-color: #4f5467; color: #ffffff; padding: 10px; border: 1px solid #3b3f54;")  # Adjusted padding
        layout.addWidget(self.quarantine_result_list)

        self.unquarantine_button = QPushButton("Unquarantine")
        self.unquarantine_button.setFont(QFont('Arial', 14))  # Larger font size
        self.unquarantine_button.setFixedSize(150, 50)  # Larger button size
        self.unquarantine_button.setStyleSheet("background-color: #e67e22; color: #ffffff; padding: 5px; border: 1px solid #3b3f54;")
        self.unquarantine_button.clicked.connect(self.unquarantine_file)
        layout.addWidget(self.unquarantine_button)

    def browse_file_or_directory(self):
        file_path = QFileDialog.getOpenFileName()[0] or QFileDialog.getExistingDirectory()
        if file_path:
            self.scan_entry.setText(file_path)

    def scan_file_or_directory(self):
        path = self.scan_entry.text()
        if not path:
            self.result_text.append("Error: No file or directory selected.")
            logging.warning("No file or directory selected for scan.")
            return

        self.result_text.clear()
        if os.path.isfile(path):
            self.result_text.append(f"Scanning file: {path}")
            if self.is_dangerous_file(path):
                self.result_text.append("File might be risky or contain malware.")
                logging.info(f"File {path} might be risky or contain malware.")
            else:
                self.result_text.append("File is safe.")
                logging.info(f"File {path} is safe.")
        elif os.path.isdir(path):
            self.result_text.append(f"Scanning directory: {path}")
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self.is_dangerous_file(file_path):
                        self.result_text.append(f"File {file_path} might be risky or contain malware.")
                        logging.info(f"File {file_path} might be risky or contain malware.")
                    else:
                        self.result_text.append(f"File {file_path} is safe.")
                        logging.info(f"File {file_path} is safe.")
        else:
            self.result_text.append("Error: Selected path is not valid.")
            logging.warning("Selected path is not valid for scan.")

    def is_dangerous_file(self, file_path):
        return self.scan_file_with_virustotal(file_path)

    def scan_file_with_virustotal(self, file_path):
        # Scan the file with VirusTotal
        with open(file_path, 'rb') as file:
            files = {'file': file}
            headers = {'x-apikey': self.virustotal_api_key}
            response = requests.post('https://www.virustotal.com/api/v3/files', files=files, headers=headers)
            if response.status_code == 200:
                scan_id = response.json()['data']['id']
                scan_url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
                response = requests.get(scan_url, headers=headers)
                if response.status_code == 200:
                    result = response.json()['data']['attributes']['status']
                    if result == 'completed':
                        results = response.json()['data']['attributes']['results']
                        if any(virus['category'] == 'malicious' for virus in results.values()):
                            return True
            return False

    def check_url(self):
        url = self.url_entry.text()
        if not url:
            self.result_text_url.append("Error: No URL provided.")
            logging.warning("No URL provided for check.")
            return

        is_safe = self.is_dangerous_url(url)
        if is_safe:
            self.result_text_url.append(f"URL {url} might be risky or contain malware.")
            logging.info(f"URL {url} might be risky or contain malware.")
        else:
            self.result_text_url.append(f"URL {url} is safe.")
            logging.info(f"URL {url} is safe.")

        final_url = self.resolve_url_redirection(url)
        self.result_text_url.append(f"Final URL: {final_url}")

    def is_dangerous_url(self, url):
        headers = {'x-apikey': self.virustotal_api_key}
        response = requests.get(f'https://www.virustotal.com/api/v3/urls', params={'url': url}, headers=headers)
        if response.status_code == 200:
            url_id = response.json()['data']['id']
            scan_url = f'https://www.virustotal.com/api/v3/analyses/{url_id}'
            response = requests.get(scan_url, headers=headers)
            if response.status_code == 200:
                result = response.json()['data']['attributes']['status']
                if result == 'completed':
                    results = response.json()['data']['attributes']['results']
                    if any(virus['category'] == 'malicious' for virus in results.values()):
                        return True
        return False

    def resolve_url_redirection(self, url):
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            return response.url
        except requests.RequestException as e:
            logging.error(f"Error resolving URL redirection: {e}")
            return "Error resolving URL redirection."

    def browse_file_for_quarantine(self):
        file_path = QFileDialog.getOpenFileName()[0]
        if file_path:
            self.quarantine_entry.setText(file_path)

    def quarantine_file(self):
        file_path = self.quarantine_entry.text()
        if not file_path or not os.path.isfile(file_path):
            self.quarantine_result_list.addItem("Error: No valid file selected.")
            logging.warning("No valid file selected for quarantine.")
            return

        file_name = os.path.basename(file_path)
        quarantine_path = os.path.join(self.quarantine_dir, file_name)
        shutil.move(file_path, quarantine_path)
        self.quarantine_result_list.addItem(f"File {file_name} quarantined.")
        logging.info(f"File {file_name} quarantined.")

    def list_quarantined_files(self):
        self.quarantine_result_list.clear()
        for file_name in os.listdir(self.quarantine_dir):
            self.quarantine_result_list.addItem(file_name)
        if not self.quarantine_result_list.count():
            self.quarantine_result_list.addItem("No quarantined files.")

    def unquarantine_file(self):
        selected_item = self.quarantine_result_list.currentItem()
        if not selected_item:
            self.quarantine_result_list.addItem("Error: No file selected to unquarantine.")
            logging.warning("No file selected to unquarantine.")
            return

        file_name = selected_item.text()
        quarantine_path = os.path.join(self.quarantine_dir, file_name)
        if not os.path.isfile(quarantine_path):
            self.quarantine_result_list.addItem(f"Error: File {file_name} does not exist.")
            logging.warning(f"File {file_name} does not exist for unquarantine.")
            return

        # Check file safety before restoring
        if self.is_dangerous_file(quarantine_path):
            self.quarantine_result_list.addItem(f"File {file_name} is considered dangerous and cannot be restored.")
            logging.info(f"File {file_name} is considered dangerous and cannot be restored.")
            return

        destination_path = QFileDialog.getExistingDirectory()
        if destination_path:
            shutil.move(quarantine_path, destination_path)
            self.quarantine_result_list.addItem(f"File {file_name} restored.")
            logging.info(f"File {file_name} restored to {destination_path}.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = AntivirusGUI()
    gui.show()
    sys.exit(app.exec_())
