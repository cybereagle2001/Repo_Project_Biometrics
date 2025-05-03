import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox, scrolledtext
import os
from datetime import datetime
from backend_2 import *

class BiometricAuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Biometric Authentication System")
        self.root.geometry("800x600")

        # Logs
        self.log_file = "operation_logs.txt"
        self.logs = []

        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Biometric Authentication Tab
        self.auth_tab = tk.Frame(self.notebook)
        self.notebook.add(self.auth_tab, text="Biometric Authentication")
        self.setup_biometric_auth_tab()

        # File Management Tab
        self.file_tab = tk.Frame(self.notebook)
        self.notebook.add(self.file_tab, text="File Management")
        self.setup_file_management_tab()

        # Enroll Fingerprint
        self.enroll_tab = tk.Frame(self.notebook)
        self.notebook.add(self.enroll_tab, text="Enroll Fingerprint")
        self.setup_enroll_tab()

        # History Tab
        self.history_tab = tk.Frame(self.notebook)
        self.notebook.add(self.history_tab, text="Operation History")
        self.setup_history_tab()


        # Disable File Management and History tabs initially
        self.notebook.tab(3, state="disabled") # disable Enroll Fingerprint
        self.notebook.tab(1, state="disabled")  # File Management tab
        self.notebook.tab(2, state="disabled")  # History tab

    def setup_biometric_auth_tab(self):
        tk.Label(self.auth_tab, text="Fingerprint Image Path:").grid(row=0, column=0, padx=10, pady=10)
        self.fingerprint_path_entry = tk.Entry(self.auth_tab, width=50)
        self.fingerprint_path_entry.grid(row=0, column=1, padx=10, pady=10)
        tk.Button(self.auth_tab, text="Browse", command=self.browse_fingerprint).grid(row=0, column=2, padx=10, pady=10)

        tk.Button(self.auth_tab, text="Verify Fingerprint", command=self.verify_fingerprint).grid(row=1, column=1, pady=20)

    def setup_file_management_tab(self):
        tk.Label(self.file_tab, text="File Path:").grid(row=0, column=0, padx=10, pady=10)
        self.file_path_entry = tk.Entry(self.file_tab, width=50)
        self.file_path_entry.grid(row=0, column=1, padx=10, pady=10)
        tk.Button(self.file_tab, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=10, pady=10)

        tk.Label(self.file_tab, text="Operation:").grid(row=1, column=0, padx=10, pady=10)
        self.operation_var = tk.StringVar(value="encrypt")
        tk.Radiobutton(self.file_tab, text="Encrypt", variable=self.operation_var, value="encrypt").grid(row=1, column=1, padx=10, pady=10)
        tk.Radiobutton(self.file_tab, text="Decrypt", variable=self.operation_var, value="decrypt").grid(row=1, column=2, padx=10, pady=10)

        tk.Button(self.file_tab, text="Execute Operation", command=self.execute_operation).grid(row=2, column=1, pady=20)

    def setup_enroll_tab(self):
        tk.Label(self.enroll_tab, text="Fingerprint Image Path:").grid(row=0, column=0, padx=10, pady=10)
        self.enroll_fingerprint_path_entry = tk.Entry(self.enroll_tab, width=50)
        self.enroll_fingerprint_path_entry.grid(row=0, column=1, padx=10, pady=10)
        tk.Button(self.enroll_tab, text="Browse", command=self.browse_enroll_fingerprint).grid(row=0, column=2, padx=10, pady=10)
        tk.Label(self.enroll_tab, text="User ID:").grid(row=1, column=0, padx=10, pady=10)
        self.user_id_entry = tk.Entry(self.enroll_tab, width=50)
        self.user_id_entry.grid(row=1, column=1, padx=10, pady=10)
        tk.Button(self.enroll_tab, text="Enroll Fingerprint", command=self.enroll_selected_fingerprint).grid(row=2, column=1, pady=20)

    def setup_history_tab(self):
        self.history_text = scrolledtext.ScrolledText(self.history_tab, width=90, height=20)
        self.history_text.pack(padx=10, pady=10)
        self.history_text.insert(tk.END, "Operation Logs:\n\n")
        self.history_text.config(state=tk.DISABLED)
        self.load_logs()

    def browse_fingerprint(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg *.tif")])
        self.fingerprint_path_entry.delete(0, tk.END)
        self.fingerprint_path_entry.insert(0, file_path)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_path_entry.delete(0, tk.END)
        self.file_path_entry.insert(0, file_path)

    def verify_fingerprint(self):
        fingerprint_path = self.fingerprint_path_entry.get()
        if not fingerprint_path:
            messagebox.showerror("Error", "Please select a fingerprint image.")
            return

        if verify_fingerprint(fingerprint_path):
            messagebox.showinfo("Success", "Fingerprint verified successfully.")
            self.log_operation(f"Fingerprint verified: {fingerprint_path}")
            # Enable File Management and History tabs after successful verification
            self.notebook.tab(1, state="normal")  # File Management tab
            self.notebook.tab(2, state="normal")  # Enroll Fingerprint
            self.notebook.tab(3, state="normal")  # History tab
        else:
            self.log_operation(f"Fingerprint Not Recognised!")
            messagebox.showerror("Error", "Fingerprint verification failed.")
    
    def browse_enroll_fingerprint(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg *.tif")])
        if file_path:
            self.enroll_fingerprint_path_entry.delete(0, tk.END)
            self.enroll_fingerprint_path_entry.insert(0, file_path)

    def enroll_selected_fingerprint(self):
        fingerprint_path = self.enroll_fingerprint_path_entry.get()
        user_id = self.user_id_entry.get()
        if not fingerprint_path or not user_id:
            messagebox.showerror("Error", "Please select a fingerprint image and enter a User ID.")
            return

        try:
            enroll_fingerprint(fingerprint_path, user_id)
            messagebox.showinfo("Success", f"Fingerprint enrolled for user '{user_id}'.")
            self.log_operation(f"Fingerprint enrolled for user: {user_id}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def execute_operation(self):
        fingerprint_path = self.fingerprint_path_entry.get()
        file_path = self.file_path_entry.get()
        operation = self.operation_var.get()

        if not fingerprint_path or not file_path:
            messagebox.showerror("Error", "Please provide both fingerprint and file paths.")
            return

        try:
            biometric_authenticate(fingerprint_path, operation, file_path)
            self.log_operation(f"{operation.capitalize()} operation performed on {file_path}")
            messagebox.showinfo("Success", f"File {operation}ed successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def log_operation(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} - {message}\n"
        self.logs.append(log_entry)
        self.history_text.config(state=tk.NORMAL)
        self.history_text.insert(tk.END, log_entry)
        self.history_text.config(state=tk.DISABLED)
        self.history_text.yview(tk.END)
        self.save_log_to_file(log_entry)

    def load_logs(self):
        if os.path.exists(self.log_file):
            with open(self.log_file, 'r') as f:
                for line in f:
                    self.logs.append(line)
                    self.history_text.config(state=tk.NORMAL)
                    self.history_text.insert(tk.END, line)
                self.history_text.config(state=tk.DISABLED)
                self.history_text.yview(tk.END)
    
    def save_log_to_file(self, log_entry):
        with open(self.log_file, 'a') as f:
            f.write(log_entry)

if __name__ == "__main__":
    root = tk.Tk()
    app = BiometricAuthApp(root)
    root.mainloop()
