
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import random
import string
from decryption_gui import *

class EncryptionGUI(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.encryption_frame = tk.Frame(self)     
        self.encryption_frame.pack()

        # Encryption section
        encryption_label = tk.Label(self.encryption_frame, text="Encryption Content")
        encryption_label.pack(padx=10, pady=10)

        encrypt_file_label = tk.Label( self.encryption_frame, text="Choose a file to encrypt:")
        encrypt_file_label.pack(padx=10, pady=5)

        self.file_entry = tk.Entry( self.encryption_frame, width=50)
        self.file_entry.pack(padx=10, pady=5)

        # Create a frame for the browse, clear, and password entry widgets
        button_frame = ttk.Frame( self.encryption_frame)
        button_frame.pack()

        # Browse button for encryption
        browse_button = tk.Button(button_frame, text="Browse", command= self.browse_encrypt_file)
        browse_button.pack(side=tk.LEFT, padx=5, pady=5)

        #password entry for encryption
        password_label = tk.Label( self.encryption_frame, text="Enter a password:")
        password_label.pack(padx=10, pady=5)

        self.password_radio_var = tk.StringVar(value="password")     

        password_radio_frame = ttk.Frame( self.encryption_frame)
        password_radio_frame.pack()

        self.password_radio_button1 = tk.Radiobutton(password_radio_frame, text="Password", variable=self.password_radio_var,
                                                value="password", command= self.toggle_password_entry)
        self.password_radio_button1.pack(side=tk.LEFT, padx=5, pady=5)

        self.password_radio_button2 = tk.Radiobutton(password_radio_frame, text="Public Key", variable=self.password_radio_var,
                                                value="public_key", command= self.toggle_password_entry)
        self.password_radio_button2.pack(side=tk.LEFT, padx=5, pady=5)

        self.password_entry = tk.Entry( self.encryption_frame, width=50, show="*")
        self.public_key_entry = tk.Entry( self.encryption_frame, width=50)
        self.private_key_entry = tk.Entry( self.encryption_frame, width=50)

        self.password_entry.insert(0, "Required**")
        self.public_key_entry.insert(0, "Recipient's Public Key**")
        self.private_key_entry.insert(0, "Your Private Key**")

        self.password_entry.bind("<FocusIn>",  self.password_entry_click)         
        self.password_entry.bind("<FocusOut>",  self.password_entry_leave)
        self.public_key_entry.bind("<FocusIn>",  self.public_key_entry_click)
        self.public_key_entry.bind("<FocusOut>",  self.public_key_entry_leave)
        self.private_key_entry.bind("<FocusIn>",  self.private_key_entry_click)
        self.private_key_entry.bind("<FocusOut>", self.private_key_entry_leave)


        # Show password checkbox for encryption
        self.show_password_var = tk.BooleanVar()
        self.show_password_checkbox = tk.Checkbutton(
             self.encryption_frame, text="Show password", variable=self.show_password_var,
            command= self.toggle_password_visibility
        )
        self.show_password_checkbox.pack(padx=10, pady=5)  # Show the checkbox
        self.show_password_checkbox.pack_forget()

        # Generate password button for encryption
        self.generate_password_button = tk.Button(
             self.encryption_frame, text="Generate Password", command= self.generate_password
        )

        # Generate key button for encryption
        self.generate_key_button = tk.Button(
             self.encryption_frame, text="Generate Key", command= self.show_key_fields
        )
        self.generate_key_button.pack(padx=10, pady=5)
        self.generate_key_button.pack_forget()# Initially hide the entry field

        # Entry fields for generated keys
        self.generated_private_key_entry = tk.Entry( self.encryption_frame, width=50)
        self.generated_private_key_entry.pack(padx=10, pady=5)
        self.generated_private_key_entry.pack_forget()  # Initially hide the entry field

        self.generated_public_key_entry = tk.Entry( self.encryption_frame, width=50)
        self.generated_public_key_entry.pack(padx=10, pady=5)
        self.generated_public_key_entry.pack_forget()  # Initially hide the entry field

        self.generate_key_pair_button = tk.Button(
             self.encryption_frame, text="Generate Key Pair", command= self.generate_keys
        )
        self.generate_key_pair_button.pack(padx=10, pady=5)
        self.generate_key_pair_button.pack_forget()  # Initially hide the entry field

        # Encrypt with RSA Keys button
        self.encrypt_with_rsa_keys_button = tk.Button( self.encryption_frame, text="Encrypt with RSA Keys", command= self.encrypt_file_with_rsa)
        self.encrypt_with_rsa_keys_button.pack(side=tk.BOTTOM, padx=10, pady=5)
        self.encrypt_with_rsa_keys_button.pack_forget()

        self.output_label_encryption = tk.Label( self.encryption_frame, text="", fg="red")
        self.output_label_encryption.pack(padx=10, pady=5)

        # Add these lines where you define your buttons
        clear_encrypt_fields_button = tk.Button( self.encryption_frame, text="Clear Fields", command= self.clear_encrypt_fields)
        clear_encrypt_fields_button.pack(side=tk.BOTTOM, padx=10, pady=5)

        self.encrypt_button = tk.Button( self.encryption_frame, text="Encrypt File", command= self.encrypt_file_with_password)
    
    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.generated_private_key_entry.delete(0, tk.END)
        self.generated_private_key_entry.insert(tk.END, private_pem.decode())
        self.generated_public_key_entry.delete(0, tk.END)
        self.generated_public_key_entry.insert(tk.END, public_pem.decode())

    def save_file(self, file_path, data):
        save_file_path = filedialog.asksaveasfilename(defaultextension=".enc")
        if save_file_path:
            try:
                with open(save_file_path, "wb") as file:
                    file.write(data)
                return True
            except Exception as e:
                print("Save failed:", e)
        return False

    def browse_encrypt_file(self):
        filename = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, filename)

    def clear_encrypt_file_entry(self):
        self.file_entry.delete(0, tk.END)

    def generate_key_from_password(self, password, salt=b"my_salt"):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))  # Can only use kdf once
        return key

    def toggle_password_entry(self):
        if self.password_radio_var.get() == "password":
            self.password_entry.pack(padx=10, pady=5)
            self.encrypt_button.pack(side=tk.BOTTOM,padx=10, pady=5)
            self.show_password_checkbox.pack(padx=10, pady=5)
            self.generate_password_button.pack(side=tk.BOTTOM,padx=10, pady=5)

            self.public_key_entry.pack_forget()
            self.private_key_entry.pack_forget()
            self.generated_private_key_entry.pack_forget()
            self.generate_key_pair_button.pack_forget()
            self.generate_key_button.pack_forget()
            self.generated_public_key_entry.pack_forget()
            self.encrypt_with_rsa_keys_button.pack_forget()
        else:
            self.password_entry.pack_forget()
            self.public_key_entry.pack(padx=10, pady=5)
            self.private_key_entry.pack(padx=10, pady=5)
            self.generate_password_button.pack_forget()
            self.show_password_checkbox.pack_forget()
            self.generate_key_button.pack(padx=10, pady=5)
            self.encrypt_button.pack_forget()
            self.encrypt_with_rsa_keys_button.pack(side=tk.BOTTOM,padx=10, pady=5)


    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def generate_password(self):
        password = os.urandom(16)
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, base64.urlsafe_b64encode(password).decode())

    def password_entry_click(self, event):
        if self.password_entry.get() == "Required**":
            self.password_entry.delete(0, tk.END)
            self.password_entry.config(foreground="white")

    def password_entry_leave(self, event):
        if not self.password_entry.get():
            self.password_entry.insert(0, "Required**")
            self.password_entry.config(foreground="gray")

    def public_key_entry_click(self, event):
        if self.public_key_entry.get() == "Recipient's Public Key**":
            self.public_key_entry.delete(0, tk.END)
            self.public_key_entry.config(foreground="white")

    def public_key_entry_leave(self, event):
        if not self.public_key_entry.get():
            self.public_key_entry.insert(0, "Recipient's Public Key**")
            self.public_key_entry.config(foreground="gray")

    def private_key_entry_click(self, event):
        if self.private_key_entry.get() == "Your Private Key**":
            self.private_key_entry.delete(0, tk.END)
            self.private_key_entry.config(foreground="white")

    def private_key_entry_leave(self, event):
        if not self.private_key_entry.get():
            self.private_key_entry.insert(0, "Your Private Key**")
            self.private_key_entry.config(foreground="gray")

    def clear_encrypt_fields(self):
        self.file_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.public_key_entry.delete(0, tk.END)
        self.private_key_entry.delete(0, tk.END)
        self.generated_private_key_entry.delete(0, tk.END)
        self.generated_public_key_entry.delete(0, tk.END)
        self.output_label_encryption.config(text="")

        if not self.password_entry.get():
            self.password_entry.insert(0, "Required**")
        if not self.public_key_entry.get():
            self.public_key_entry.insert(0, "Recipient's Public Key**")
        if not self.private_key_entry.get():
            self.private_key_entry.insert(0, "Your Private Key**")

    def encrypt_file_with_password(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()

        if not file_path or file_path == "Required**":
            messagebox.showerror("Error", "No file chosen for encryption.")
            return

        if not password or password == "Required**":
            messagebox.showerror("Error", "No password entered for encryption.")
            return
        if not os.path.isfile(file_path):
            self.output_label_encryption.config(text="File not found.", fg="red")
            return

        try:
            with open(file_path, "rb") as file:
                data = file.read()

            fernet = Fernet(self.generate_key_from_password(password))
            encrypted_data = fernet.encrypt(data)

            if self.save_file(file_path, encrypted_data):
                self.output_label_encryption.config(text="File encrypted and saved successfully!", fg="green")
            else:
                self.output_label_encryption.config(text="Encryption failed: Failed to save file.", fg="red")

        except Exception as e:
                self.output_label_encryption.config(text="Encryption failed: " + str(e), fg="red")



    def encrypt_file_with_password(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()

        if not file_path or file_path == "Required**":
            messagebox.showerror("Error", "No file chosen for encryption.")
            return

        if not password or password == "Required**":
            messagebox.showerror("Error", "No password entered for encryption.")
            return
        if not os.path.isfile(file_path):
            self.output_label_encryption.config(text="File not found.",fg="red")
            return

        try:
            with open(file_path, "rb") as file:
                data = file.read()

            fernet = Fernet(self.generate_key_from_password(password))
            encrypted_data = fernet.encrypt(data)

            if self.save_file(file_path, encrypted_data):
                self.output_label_encryption.config(text="File encrypted and saved successfully!",fg="green")
            else:
                self.output_label_encryption.config(text="Encryption failed: Failed to save file.",fg="red")

        except Exception as e:
            self.output_label_encryption.config(text="Encryption failed: " + str(e),fg="red")



    def encrypt_file_with_rsa(self):
        file_path = self.file_entry.get()
        public_key_pem = self.public_key_entry.get()

        if not file_path or file_path == "Required**":
            messagebox.showerror("Error", "No file chosen for encryption.")
            return

        if not public_key_pem or public_key_pem == "Recipient's Public Key**":
            messagebox.showerror("Error", "No public key entered for encryption.")
            return

        # Read the file data
        try:
            with open(file_path, "rb") as file:
                data = file.read()
        except IOError:
            self.output_label_encryption.config(text="File not found.", fg="red")
            return

        # Load the recipient's public key
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
        except ValueError:
            self.output_label_encryption.config(text="Invalid public key.", fg="red")
            return

        # Generate a random symmetric key
        symmetric_key = os.urandom(32)

        # Encrypt the data with the symmetric key
        aesgcm = AESGCM(symmetric_key)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, data, None)

        # Encrypt the symmetric key with the public key
        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Concatenate the encrypted key, nonce, and encrypted data
        final_data = encrypted_key + nonce + encrypted_data

        if self.save_file(file_path, final_data):
            self.output_label_encryption.config(text="File encrypted and saved successfully!", fg="green")
        else:
            self.output_label_encryption.config(text="Encryption failed: Failed to save file.", fg="red")

    def show_key_fields(self):
        self.generated_public_key_entry.pack(padx=10, pady=5)
        self.generated_private_key_entry.pack(padx=10, pady=5)
        self.generate_key_pair_button.pack(padx=10, pady=5)

    def get_frame(self):
        return self.encryption_frame

    