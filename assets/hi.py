import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# Function to derive a key from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt file
def encrypt_file(filepath, password):
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        salt = os.urandom(16)
        key = derive_key(password, salt)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)

        new_file = filepath + ".enc"
        with open(new_file, "wb") as f:
            f.write(salt + encrypted)

        messagebox.showinfo("Success", f"File encrypted: {new_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Decrypt file
def decrypt_file(filepath, password):
    try:
        with open(filepath, "rb") as f:
            content = f.read()

        salt = content[:16]
        encrypted_data = content[16:]
        key = derive_key(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data)

        original_file = filepath.replace(".enc", ".dec")
        with open(original_file, "wb") as f:
            f.write(decrypted)

        messagebox.showinfo("Success", f"File decrypted: {original_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI
def select_file_encrypt():
    filepath = filedialog.askopenfilename()
    password = password_entry.get()
    if filepath and password:
        encrypt_file(filepath, password)
    else:
        messagebox.showwarning("Input Required", "Select file and enter password")

def select_file_decrypt():
    filepath = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
    password = password_entry.get()
    if filepath and password:
        decrypt_file(filepath, password)
    else:
        messagebox.showwarning("Input Required", "Select file and enter password")

# Window setup
root = tk.Tk()
root.title("File Encryption/Decryption Tool")
root.geometry("400x200")
root.resizable(False, False)

# Widgets
tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
password_entry = tk.Entry(root, show="*", width=40)
password_entry.pack()

tk.Button(root, text="Encrypt File", command=select_file_encrypt, bg="green", fg="white", width=20).pack(pady=10)
tk.Button(root, text="Decrypt File", command=select_file_decrypt, bg="blue", fg="white", width=20).pack(pady=5)

# Start GUI loop
root.mainloop()
