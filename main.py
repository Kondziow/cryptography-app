import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import xml.etree.ElementTree as ET
import os
import datetime

class SignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Electronic Signature Emulation")

        # Setup frames
        self.frame = tk.Frame(self.root)
        self.frame.pack(padx=50, pady=50)

        # File selection
        self.filepath = tk.StringVar()
        self.file_label = tk.Label(self.frame, text="No file selected")
        self.file_label.pack(side=tk.TOP, fill=tk.X, expand=True)

        self.select_button = tk.Button(self.frame, text="Select File", command=self.select_file)
        self.select_button.pack(side=tk.TOP, pady=5)

        # Sign button
        self.sign_button = tk.Button(self.frame, text="Sign Document", command=self.sign_document)
        self.sign_button.pack(side=tk.TOP, pady=5)

        # Encrypt/Decrypt button
        self.encdec_button = tk.Button(self.frame, text="Encrypt/Decrypt File", command=self.encrypt_decrypt)
        self.encdec_button.pack(side=tk.TOP, pady=5)

        # Status message
        self.status = tk.StringVar()
        self.status_label = tk.Label(self.frame, textvariable=self.status)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, expand=True)

    def select_file(self):
        file_types = [('PDF files', '*.pdf'), ('C++ Source files', '*.cpp')]
        filepath = filedialog.askopenfilename(title="Select a file", filetypes=file_types)
        if filepath:
            self.filepath.set(filepath)
            self.file_label.config(text=f"Selected: {filepath}")
            self.status.set("File selected successfully.")
        else:
            self.status.set("File selection cancelled.")

    def sign_document(self):
        if not self.filepath.get():
            messagebox.showerror("Error", "No file selected!")
            self.status.set("Select a file to sign.")
            return

        # Read the content of the file
        try:
            with open(self.filepath.get(), 'rb') as f:
                document_data = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read the file: {str(e)}")
            return

        # Calculate the hash of the document
        document_hash = hashlib.sha256(document_data).hexdigest()

        # Sign the hash using the private RSA key
        try:
            signature = self.private_key.sign(
                document_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to sign the document: {str(e)}")
            return

        # Generate XML signature file
        root = ET.Element("Signature")
        ET.SubElement(root, "DocumentHash").text = document_hash
        ET.SubElement(root, "Signature").text = signature.hex()
        ET.SubElement(root, "Timestamp").text = datetime.datetime.now().isoformat()

        tree = ET.ElementTree(root)
        xml_file_name = os.path.basename(self.filepath.get()) + ".signature.xml"
        tree.write(xml_file_name)

        self.status.set(f"Document signed successfully. Signature saved to {xml_file_name}")

    def encrypt_decrypt(self):
        if not self.filepath.get():
            messagebox.showerror("Error", "No file selected!")
            self.status.set("Select a file to encrypt/decrypt.")
            return
        # Placeholder for encryption/decryption logic
        self.status.set("File encrypted/decrypted successfully (placeholder).")

def generate_rsa_keys():
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    # Export the private key in PEM format
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generate the public key
    public_key = private_key.public_key()
    # Export the public key in PEM format
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private, pem_public

# Output the keys to console or write to files
# print("Private Key:")
# print(private_key.decode())
# print("\nPublic Key:")
# print(public_key.decode())


if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys()
    root = tk.Tk()
    app = SignatureApp(root)
    app.private_key = serialization.load_pem_private_key(
        private_key,
        password=None
    )
    app.public_key = serialization.load_pem_public_key(
        public_key
    )
    root.mainloop()