import tkinter as tk
from tkinter import filedialog, messagebox

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from xml.etree import ElementTree as ET
from xml.dom import minidom
import datetime
import os

class SignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Electronic Signature Emulation")

        # Initialize paths
        self.filepath = None
        self.public_key = None
        self.private_key = None
        self.signature_file_path = None

        # Setup frames
        self.top_frame = tk.Frame(self.root)
        self.top_frame.pack(padx=20, pady=20, fill=tk.X)

        # Setup options with icons
        self.options = [
            ("Select Document", self.select_file),
            ("Select Public Key", self.select_public_key),
            ("Select Private Key", self.select_private_key),
            ("Select Signature", self.select_signature)
        ]
        self.icons = {}

        for option, command in self.options:
            frame = tk.Frame(self.top_frame)
            frame.pack(side=tk.LEFT, expand=True, padx=10)

            label = tk.Label(frame, text=option)
            label.pack(pady=5)

            button = tk.Button(frame, text="Select", command=command)
            button.pack()

            icon_label = tk.Label(frame, text="❌", fg="red")
            icon_label.pack()
            self.icons[option] = icon_label

        # Additional buttons
        self.sign_button = tk.Button(self.root, text="Sign Document", command=self.sign_document, state=tk.DISABLED)
        self.sign_button.pack(pady=5)

        self.verify_button = tk.Button(self.root, text="Verify Signature", command=self.verify_signature,state=tk.DISABLED)
        self.verify_button.pack(pady=5)

        self.keygen_button = tk.Button(self.root, text="Generate RSA Keys", command=self.generate_rsa_keys)
        self.keygen_button.pack(pady=5)

        # Status message
        self.status = tk.StringVar()
        self.status_label = tk.Label(self.root, textvariable=self.status)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    def update_verify_button_state(self):
        # Enable the verify button only if all required files are loaded
        if self.public_key and self.signature_file_path and self.filepath:
            self.verify_button['state'] = tk.NORMAL
        else:
            self.verify_button['state'] = tk.DISABLED
    def update_sign_button_state(self):
        if self.filepath and self.public_key and self.private_key:
            self.sign_button['state'] = tk.NORMAL
        else:
            self.sign_button['state'] = tk.DISABLED

    def select_file(self):
        file_types = [('PDF files', '*.pdf'), ('C++ Source files', '*.cpp'), ('All files', '*.*')]
        initial_dir = os.getcwd()
        self.filepath = filedialog.askopenfilename(title="Select a file", initialdir=initial_dir, filetypes=file_types)
        if self.filepath:
            self.update_icon("Select Document", True)
            self.status.set("File selected successfully.")
        else:
            self.update_icon("Select Document", False)
            self.status.set("File selection cancelled.")
        self.update_sign_button_state()
        self.update_verify_button_state()

    def select_public_key(self):
        file_types = [('PEM files', '*.pem')]
        public_key_path = filedialog.askopenfilename(title="Select Public Key File", initialdir=os.getcwd(),
                                                     filetypes=file_types)
        if public_key_path:
            try:
                with open(public_key_path, 'rb') as f:
                    public_key_data = f.read()
                    self.public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())
                self.update_icon("Select Public Key", True)
                self.status.set("Public key loaded successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load public key: {str(e)}")
                self.update_icon("Select Public Key", False)
                self.status.set("Failed to load public key.")
        else:
            self.update_icon("Select Public Key", False)
            self.status.set("Public key selection cancelled.")
        self.update_sign_button_state()
        self.update_verify_button_state()

    def select_private_key(self):
        file_types = [('PEM files', '*.pem')]
        private_key_path = filedialog.askopenfilename(title="Select Private Key File", initialdir=os.getcwd(),
                                                      filetypes=file_types)
        if private_key_path:
            try:
                with open(private_key_path, 'rb') as f:
                    private_key_data = f.read()
                    self.private_key = serialization.load_pem_private_key(private_key_data, password=None, backend=default_backend())
                self.update_icon("Select Private Key", True)
                self.status.set("Private key loaded successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load private key: {str(e)}")
                self.update_icon("Select Private Key", False)
                self.status.set("Failed to load private key.")
        else:
            self.update_icon("Select Private Key", False)
            self.status.set("Private key selection cancelled.")
        self.update_sign_button_state()

    def select_signature(self):
        file_types = [('XML files', '*.xml')]
        signature_file_path = filedialog.askopenfilename(title="Select Signature File", initialdir=os.getcwd(),
                                                         filetypes=file_types)

        if signature_file_path:
            self.signature_file_path = signature_file_path
            self.update_icon("Select Signature", True)
            self.status.set("Signature file selected successfully.")
        else:
            self.update_icon("Select Signature", False)
            self.status.set("Signature file selection cancelled.")

        self.update_verify_button_state()

    def update_icon(self, option, success):
        icon_label = self.icons[option]
        if success:
            icon_label.config(text="✔️", fg="green")
        else:
            icon_label.config(text="❌", fg="red")

    def sign_document(self):
        try:
            with open(self.filepath, 'rb') as f:
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

        xml_file_name = os.path.basename(self.filepath) + ".signature.xml"
        with open(xml_file_name, 'w') as xml_file:
            xml_file.write(pretty_xml)

        self.status.set(f"Document signed successfully. Signature saved to {xml_file_name}")

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

        self.update_sign_button_state()
        self.update_icon("Select Public Key", True)
        self.update_icon("Select Private Key", True)

    def verify_signature(self):
        try:
            with open(self.filepath, 'rb') as f:
                document_data = f.read()
            document_hash = hashlib.sha256(document_data).digest()

            # Load the signature XML
            tree = ET.parse(self.signature_file_path)
            root = tree.getroot()
            signature = bytes.fromhex(root.find('Signature').text)

            # Verify the signature using the already loaded public key
            self.public_key.verify(
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