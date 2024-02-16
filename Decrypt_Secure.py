import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os

class FileDecryptor:
    def __init__(self, master):
        self.master = master
        self.master.title("File Decryption with RSA")
        self.create_widgets()

    def create_widgets(self):
        self.label_public = tk.Label(self.master, text="Select RSA Public Key File:")
        self.label_public.pack()

        self.key_button_public = tk.Button(self.master, text="Browse", command=self.select_public_key)
        self.key_button_public.pack()

        self.label_private = tk.Label(self.master, text="Select RSA Private Key File:")
        self.label_private.pack()

        self.key_button_private = tk.Button(self.master, text="Browse", command=self.select_private_key)
        self.key_button_private.pack()

        self.decrypt_button = tk.Button(self.master, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack()

    def select_public_key(self):
        file_path = filedialog.askopenfilename(title="Select RSA Public Key File", filetypes=[("Public Key Files", "*.pem")])
        if file_path:
            self.public_key_path = file_path
            self.label_public.config(text=f"Selected Public Key: {self.public_key_path}")

    def select_private_key(self):
        file_path = filedialog.askopenfilename(title="Select RSA Private Key File", filetypes=[("Private Key Files", "*.pem")])
        if file_path:
            self.private_key_path = file_path
            self.label_private.config(text=f"Selected Private Key: {self.private_key_path}")

    def decrypt_file(self):
        if not (hasattr(self, 'public_key_path') and hasattr(self, 'private_key_path')):
            messagebox.showerror("Error", "Please select both RSA public and private keys.")
            return

        encrypted_file_path = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Encrypted Files", "*.enc")])
        if not encrypted_file_path:
            return

        with open(self.private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # You may need to provide the password if the private key is protected
                backend=None
            )

        with open(encrypted_file_path, "rb") as file:
            ciphertext = file.read()

        try:
            plaintext = private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(),
                                                                     label=None))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            return

        decrypted_file_path = filedialog.asksaveasfilename(defaultextension=".dec", filetypes=[("Decrypted Files", "*.dec")])
        if decrypted_file_path:
            with open(decrypted_file_path, "wb") as decrypted_file:
                decrypted_file.write(plaintext)
            messagebox.showinfo("Success", "File decrypted successfully.")

            # Remove the original encrypted file after successful decryption
            os.remove(encrypted_file_path)
            messagebox.showinfo("Success", f"Encrypted file removed: {encrypted_file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileDecryptor(root)
    root.mainloop()
