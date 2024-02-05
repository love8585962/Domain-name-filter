import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QTextEdit, QComboBox, QLineEdit, QPushButton, QFileDialog
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QTimer
import pyperclip
import dns.resolver
import os

class NSLookupApp(QMainWindow):    
    def __init__(self):       
        super().__init__()

        self.setGeometry(320, 380, 600, 300)
        self.setWindowTitle("憑證小工具")
        self.setFixedSize(320, 380)

        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.bundle_path = os.path.join(script_dir, "bundle.txt")
        self.icon_path = os.path.join(script_dir, "2.ico")
        self.setWindowIcon(QIcon(self.icon_path))

        self.dns_options = [
            "8.8.8.8 (Google DNS1)",
            "8.8.4.4 (Google DNS2)",
            "1.1.1.1 (Cloudflare)",
            "168.95.1.1 (HiNet (TW))",
            "94.140.14.14 (AdGuard (CY))",
            "165.87.13.129 (AT&T (US))",
            "8.26.56.26 (Comodo (US))",
            "144.217.51.168 (Securolytics (CA))",
            "195.129.12.122 (UUNET (CH))",
            "64.6.64.6 (Verisign (US))",
            "77.88.8.8 (Yandex (RU))",
            "9.9.9.9 (Quad9)"
        ]

        self.initUI()

    def initUI(self):
        self.first_ip = None

        self.dns_label = QLabel('選擇 DNS:', self)
        self.dns_label.move(10, 10)

        self.dns_combobox = QComboBox(self)
        self.dns_combobox.addItems(self.dns_options)
        self.dns_combobox.setGeometry(80, 10, 200, 25)

        self.domain_entry_label = QLabel('輸入要解析的域名: (域名中間用空白間隔)', self)
        self.domain_entry_label.move(10, 35) 

        self.domain_entry = QLineEdit(self)
        self.domain_entry.setGeometry(10, 60, 300, 25)

        self.lookup_button = QPushButton('解析域名', self)
        self.lookup_button.setGeometry(10, 90, 80, 25)
        self.lookup_button.clicked.connect(self.start_nslookup)

        self.output_label = QLabel('解析域名:', self)
        self.output_label.move(10, 120)

        self.output_text = QTextEdit(self)
        self.output_text.setGeometry(10, 145, 300, 100)

        self.filtered_output_label = QLabel('篩選結果:', self)
        self.filtered_output_label.move(10, 240) 

        self.filtered_output_text = QTextEdit(self)
        self.filtered_output_text.setGeometry(10, 265, 300, 100)

        self.copy_domain_button = QPushButton('複製域名', self)
        self.copy_domain_button.setGeometry(95, 90, 80, 25)
        self.copy_domain_button.clicked.connect(self.copy_domains)

        self.completion_label = QLabel('解析完成', self)
        self.completion_label.move(65, 119)
        self.completion_label.setStyleSheet('color: red')
        self.completion_label.hide()

        self.bundle_label = QLabel('bundle 新增完成', self)
        self.bundle_label.move(65, 119)
        self.bundle_label.setStyleSheet('color: red')
        self.bundle_label.hide()

        self.browse_button = QPushButton('瀏覽憑證並新增budle', self)
        self.browse_button.setGeometry(180, 90, 130, 25)
        self.browse_button.clicked.connect(self.browse_file)

    def start_nslookup(self):
        self.output_text.clear()
        self.filtered_output_text.clear()
        self.completion_label.hide()
        self.bundle_label.hide()

        selected_dns = self.dns_combobox.currentText().split()[0]
        domains = self.domain_entry.text().split()

        QTimer.singleShot(10, lambda: self.perform_nslookup(domains, selected_dns))

    def perform_nslookup(self, domains, selected_dns):
        if not domains:
            self.show_completion_message()
            return

        domain = domains.pop(0)

        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [selected_dns]
            result = resolver.query(domain)

            for rdata in result:
                ip_address = rdata.address
                result_str = f"{domain}: {ip_address}\n"

                if self.first_ip is None:
                    self.first_ip = ip_address
                elif ip_address != self.first_ip:
                    self.filtered_output_text.insertPlainText(f"{domain}: {ip_address}\n")

                self.output_text.insertPlainText(result_str)

        except dns.exception.DNSException as e:
            error_message = f"{domain}: 無解析\n"
            self.output_text.insertPlainText(f"Cannot resolve {domain}: {e}\n")
            self.filtered_output_text.insertPlainText(error_message)

        if domains:
            QTimer.singleShot(10, lambda: self.perform_nslookup(domains, selected_dns))
        else:
            self.show_completion_message()

    def show_completion_message(self):
        self.completion_label.show()
        self.update()

    def show_bundle_add_message(self):
        self.bundle_label.show()
        self.update()

    def copy_domains(self):
        filtered_domains = self.filtered_output_text.toPlainText().splitlines()
        domains_to_copy = [line.split(":")[0] for line in filtered_domains]
        joined_domains = "\n".join(domains_to_copy)
        pyperclip.copy(joined_domains)

    def browse_file(self):
        self.completion_label.hide()
        self.bundle_label.hide()
        self.output_text.clear()
        self.filtered_output_text.clear()
        file_path, _ = QFileDialog.getOpenFileName(self, "選擇檔案", "", "CRT 檔案 (*.crt)")
        if file_path:
            self.replace_bundle(file_path)

    def replace_bundle(self, file_path=None):
        try:
            with open(self.bundle_path, "r") as bundle_file:
                content_to_append = bundle_file.read()

            if file_path:
                with open(file_path, "a") as file:
                    file.write(content_to_append)
                    self.show_bundle_add_message()
                print("新增Bundle完成")

                self.output_text.clear()
                self.output_text.insertPlainText(f"{content_to_append}")

        except Exception as e:
            print(f"發生錯誤: {e}")

def main():
    app = QApplication(sys.argv)
    window = NSLookupApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
