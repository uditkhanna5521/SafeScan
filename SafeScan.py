import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import requests
import hashlib
import os
import threading

# Replace 'your_api_key_here' with your actual VirusTotal API key
API_KEY = 'your_api_key_here'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

class SafeScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SafeScan")
        self.root.geometry("600x400")
        self.root.resizable(False, False)

        # Background color
        self.root.configure(bg='#1D1B41')

        # Title label
        self.title_label = tk.Label(self.root, text="SafeScan", font=("Helvetica", 24, "bold"), fg="#FFFFFF", bg='#1D1B41')
        self.title_label.place(relx=0.5, rely=0.3, anchor="center")

        # Status label
        self.status_label = tk.Label(self.root, text="Your system is protected", font=("Helvetica", 14), fg="#FFFFFF", bg='#1D1B41')
        self.status_label.place(relx=0.5, rely=0.4, anchor="center")

        # Scan button
        self.scan_button = tk.Button(self.root, text="RUN SMART SCAN", font=("Helvetica", 14, "bold"), fg="#FFFFFF", bg="#43B581", activebackground="#3A9248", activeforeground="#FFFFFF", command=self.scan_file)
        self.scan_button.place(relx=0.5, rely=0.5, anchor="center")

    def scan_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        self.status_label.config(text="Scanning in progress...", fg="#FFD700")
        threading.Thread(target=self.check_file, args=(file_path,)).start()

    def check_file(self, file_path):
        # Calculate the file hash (SHA-256)
        file_hash = self.calculate_file_hash(file_path)

        # Check the file hash on VirusTotal
        params = {'apikey': API_KEY, 'resource': file_hash}
        response = requests.get(REPORT_URL, params=params)

        if response.status_code == 200:
            result = response.json()
            if result.get('response_code') == 1:
                if result.get('positives', 0) > 0:
                    self.handle_malware(file_path)
                else:
                    self.show_message("No malware detected.", "#43B581")
            else:
                self.show_message("File not found in VirusTotal database.", "#FFA500")
        else:
            self.show_message("Failed to retrieve the scan report.", "#FF0000")

    def handle_malware(self, file_path):
        response = messagebox.askquestion("Alert", "Malicious file detected! Do you want to delete it?")
        if response == 'yes':
            self.delete_file(file_path)
        else:
            self.show_message("File retained.", "#43B581")

    def calculate_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def delete_file(self, file_path):
        try:
            os.remove(file_path)
            self.show_message("File deleted successfully.", "#43B581")
        except Exception as e:
            self.show_message(f"Failed to delete the file: {e}", "#FF0000")

    def show_message(self, message, color):
        self.status_label.config(text=message, fg=color)

if __name__ == "__main__":
    root = tk.Tk()
    app = SafeScanApp(root)
    root.mainloop()
