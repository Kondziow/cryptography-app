import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from xml.etree import ElementTree as ET
from xml.dom import minidom
import datetime
import os

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

        # Verify signature button
        self.verify_button = tk.Button(self.frame, text="Verify Signature", command=self.verify_signature)
        self.verify_button.pack(side=tk.TOP, pady=5)

        # Encrypt/Decrypt button
        self.encdec_button = tk.Button(self.frame, text="Encrypt/Decrypt File", command=self.encrypt_decrypt)
        self.encdec_button.pack(side=tk.TOP, pady=5)

        # Generate keys button
        self.keygen_button = tk.Button(self.frame, text="Generate RSA Keys", command=self.generate_rsa_keys)
        self.keygen_button.pack(side=tk.TOP, pady=5)

        # Status message
        self.status = tk.StringVar()
        self.status_label = tk.Label(self.frame, textvariable=self.status)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, expand=True)

    def select_file(self):
        file_types = [('PDF files', '*.pdf'), ('C++ Source files', '*.cpp')]
        initial_dir = os.getcwd()  # Gets the current working directory
        filepath = filedialog.askopenfilename(title="Select a file", initialdir=initial_dir, filetypes=file_types)
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

        try:
            with open(self.filepath.get(), 'rb') as f:
                document_data = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read the file: {str(e)}")
            return

        document_hash = hashlib.sha256(document_data).digest()

        try:
            signature = self.private_key.sign(
                document_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to sign the document: {str(e)}")
            return

        root = ET.Element("Signature")
        ET.SubElement(root, "DocumentHash").text = document_hash.hex()
        ET.SubElement(root, "Signature").text = signature.hex()
        ET.SubElement(root, "Timestamp").text = datetime.datetime.now().isoformat()

        rough_string = ET.tostring(root, 'utf-8')
        reparsed = minidom.parseString(rough_string)
        pretty_xml = reparsed.toprettyxml(indent="  ")

        xml_file_name = os.path.basename(self.filepath.get()) + ".signature.xml"
        with open(xml_file_name, 'w') as xml_file:
            xml_file.write(pretty_xml)

        self.status.set(f"Document signed successfully. Signature saved to {xml_file_name}")

    def encrypt_decrypt(self):
        if not self.filepath.get():
            messagebox.showerror("Error", "No file selected!")
            self.status.set("Select a file to encrypt/decrypt.")
            return
        self.status.set("File encrypted/decrypted successfully (placeholder).")

    def generate_rsa_keys(self):
        try:
            # Generate private key
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )

            # Export private key to PEM format
            pem_private = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Generate public key from private key
            self.public_key = self.private_key.public_key()

            # Export public key to PEM format
            pem_public = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Save keys to files in a 'keys' directory in the current program directory
            keys_dir = os.path.join(os.getcwd(), 'keys')
            if not os.path.exists(keys_dir):
                os.makedirs(keys_dir)
            with open(os.path.join(keys_dir, 'private_key.pem'), 'wb') as f:
                f.write(pem_private)
            with open(os.path.join(keys_dir, 'public_key.pem'), 'wb') as f:
                f.write(pem_public)

            self.status.set("RSA keys generated and saved successfully in 'keys' folder.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate RSA keys: {str(e)}")
            self.status.set("RSA key generation failed.")

    def verify_signature(self):
        signature_file = filedialog.askopenfilename(title="Select the signature XML file",
                                                    filetypes=[('XML files', '*.xml')])
        if not signature_file:
            messagebox.showerror("Error", "No signature file selected!")
            return

        public_key_file = filedialog.askopenfilename(title="Select the public key PEM file",
                                                     filetypes=[('PEM files', '*.pem')])
        if not public_key_file:
            messagebox.showerror("Error", "No public key file selected!")
            return

        document_file = filedialog.askopenfilename(title="Select the original document file",
                                                   filetypes=[('All files', '*.*')])
        if not document_file:
            messagebox.showerror("Error", "No document file selected!")
            return

        try:
            with open(document_file, 'rb') as f:
                document_data = f.read()
            document_hash = hashlib.sha256(document_data).digest()

            with open(public_key_file, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())

            # Load the signature XML
            tree = ET.parse(signature_file)
            root = tree.getroot()
            signature = bytes.fromhex(root.find('Signature').text)

            # Verify the signature
            public_key.verify(
                signature,
                document_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.status.set("Signature is valid.")
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {str(e)}")
            self.status.set("Verification failed.")

if __name__ == "__main__":
    root = tk.Tk()
    app = SignatureApp(root)
    root.mainloop()
