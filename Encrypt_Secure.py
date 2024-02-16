import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os

class FileEncryptor:
    def __init__(self, master):
        self.master = master
        self.master.title("File Encryption with RSA")
        self.create_widgets()

    def create_widgets(self):
        self.label = tk.Label(self.master, text="Select RSA Public Key File:")
        self.label.pack()

        self.key_button = tk.Button(self.master, text="Browse", command=self.select_public_key)
        self.key_button.pack()

        self.encrypt_button = tk.Button(self.master, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack()

    def select_public_key(self):
        file_path = filedialog.askopenfilename(title="Select RSA Public Key File", filetypes=[("Public Key Files", "*.pem")])
        if file_path:
            self.public_key_path = file_path
            self.label.config(text=f"Selected Public Key: {self.public_key_path}")

    def encrypt_file(self):
        if not hasattr(self, 'public_key_path'):
            messagebox.showerror("Error", "Please select an RSA public key first.")
            return

        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not file_path:
            return

        with open(self.public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        with open(file_path, "rb") as file:
            plaintext = file.read()

        ciphertext = public_key.encrypt(plaintext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                algorithm=hashes.SHA256(),
                                                                label=None))

        encrypted_file_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
        if encrypted_file_path:
            with open(encrypted_file_path, "wb") as encrypted_file:
                encrypted_file.write(ciphertext)
            messagebox.showinfo("Success", "File encrypted successfully.")

            # Remove the original file after successful encryption
            os.remove(file_path)
            messagebox.showinfo("Success", f"Original file removed: {file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptor(root)
    root.mainloop()
