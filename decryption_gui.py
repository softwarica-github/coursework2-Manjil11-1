import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox
from tkinter import filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import InvalidToken, InvalidSignature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.backends import default_backend
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



class DecryptionGUI(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

        decryption_label = tk.Label(self, text="Decryption Content")
        decryption_label.pack(padx=10, pady=10)

        decrypt_file_label = tk.Label(self, text="Choose a file to decrypt:")
        decrypt_file_label.pack(padx=10, pady=5)

        self.decrypt_file_entry = tk.Entry(self, width=50)
        self.decrypt_file_entry.pack(padx=10, pady=5)

        button_frame_decryption = ttk.Frame(self)
        button_frame_decryption.pack()

        browse_button_decryption = tk.Button(button_frame_decryption, text="Browse", command=self.browse_decrypt_file)
        browse_button_decryption.pack(side=tk.LEFT, padx=5, pady=5)


        password_label_decryption = tk.Label(self, text="Enter the password:")
        password_label_decryption.pack(padx=10, pady=5)

        self.password_radio_var_decryption = tk.StringVar(value="password")

        password_radio_frame_decryption = ttk.Frame(self)
        password_radio_frame_decryption.pack()

        password_radio_button1_decryption = tk.Radiobutton(
            password_radio_frame_decryption, text="Password",
            variable=self.password_radio_var_decryption, value="password",
            command=self.toggle_password_entry_decryption
        )
        password_radio_button1_decryption.pack(side=tk.LEFT, padx=5, pady=5)

        password_radio_button2_decryption = tk.Radiobutton(
            password_radio_frame_decryption, text="Private Key",
            variable=self.password_radio_var_decryption, value="private_key",
            command=self.toggle_password_entry_decryption
        )
        password_radio_button2_decryption.pack(side=tk.LEFT, padx=5, pady=5)

        self.password_entry_decryption = tk.Entry(self, width=50, show="*")
        self.public_key_entry_decryption = tk.Entry(self, width=50)
        self.private_key_entry_decryption = tk.Entry(self, width=50)

        self.password_entry_decryption.insert(0, "Required**")
        self.public_key_entry_decryption.insert(0, "Recipient's Public Key**")
        self.private_key_entry_decryption.insert(0, "Your Private Key**")

        self.password_entry_decryption.bind("<FocusIn>", self.password_entry_decryption_click)
        self.password_entry_decryption.bind("<FocusOut>", self.password_entry_decryption_leave)
        self.public_key_entry_decryption.bind("<FocusIn>", self.public_key_entry_decryption_click)
        self.public_key_entry_decryption.bind("<FocusOut>", self.public_key_entry_decryption_leave)
        self.private_key_entry_decryption.bind("<FocusIn>", self.private_key_entry_decryption_click)
        self.private_key_entry_decryption.bind("<FocusOut>", self.private_key_entry_decryption_leave)

        self.show_password_var_decryption = tk.BooleanVar()
        self.show_password_checkbox_decryption = tk.Checkbutton(
            self, text="Show password", variable=self.show_password_var_decryption,
            command=self.toggle_password_visibility_decryption
        )
        self.show_password_checkbox_decryption.pack(padx=10, pady=5)
        self.show_password_checkbox_decryption.pack_forget()

        self.decrypt_button = tk.Button(self, text="Decrypt File", command=self.decrypt_file_with_password)

        self.decrypt_with_rsa_keys_button = tk.Button(
            self, text="Decrypt with RSA Keys", command=self.decrypt_file_with_rsa
        )

        self.output_label_decryption = tk.Label(self, text="", fg="red")
        self.output_label_decryption.pack(side=tk.BOTTOM,padx=10, pady=5)

        clear_decrypt_fields_button = tk.Button(self, text="Clear Fields", command=self.clear_decrypt_fields)
        clear_decrypt_fields_button.pack(padx=10, pady=5)



    def browse_decrypt_file(self):
        filename = filedialog.askopenfilename()
        self.decrypt_file_entry.delete(0, tk.END)
        self.decrypt_file_entry.insert(0, filename)


    def save_file(self, file_path, data):
        save_file_path = filedialog.asksaveasfilename(defaultextension=".dec")
        if save_file_path:
            try:
                with open(save_file_path, "wb") as file:
                    file.write(data)
                return True
            except Exception as e:
                print("Save failed:", e) 
        return False


    def decrypt_file_with_password(self):
        file_path = self.decrypt_file_entry.get()
        password = self.password_entry_decryption.get()

        if not file_path or file_path == "Required**":
            messagebox.showerror("Error", "No file chosen for decryption.")
            return

        if not password or password == "Required**":
            messagebox.showerror("Error", "No password entered for decryption.")
            return
        if not os.path.isfile(file_path):
            self.output_label_decryption.config(text="File not found.", fg="red")
            return

        try:
            with open(file_path, "rb") as file:
                encrypted_data = file.read()

            fernet = Fernet(self.generate_key_from_password(password))
            decrypted_data = fernet.decrypt(encrypted_data)

            if self.save_file(file_path, decrypted_data):
                self.output_label_decryption.config(text="File decrypted and saved successfully!", fg='green')
            else:
                self.output_label_decryption.config(text="Decryption failed: Failed to save file.", fg="red")

        except (InvalidToken, InvalidSignature) as e:
            self.output_label_decryption.config(text="Decryption failed: Invalid password or key.", fg="red")
        except Exception as e:
            self.output_label_decryption.config(text="Decryption failed: " + str(e), fg="red")

    def decrypt_file_with_rsa(self):
        file_path = self.decrypt_file_entry.get()
        private_key_pem = self.private_key_entry_decryption.get()

        if not file_path or file_path == "Required**":
            messagebox.showerror("Error", "No file chosen for decryption.")
            return

        if not private_key_pem or private_key_pem == "Your Private Key**":
            messagebox.showerror("Error", "No private key entered for decryption.")
            return

        try:
            with open(file_path, "rb") as file:
                final_data = file.read()
        except IOError:
            self.output_label_decryption.config(text="File not found.", fg="red")
            return

        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )
        except ValueError:
            self.output_label_decryption.config(text="Invalid private key.", fg="red")
            return

        encrypted_key = final_data[:256]
        nonce = final_data[256:256 + 12]
        encrypted_data = final_data[256 + 12:]

        try:
            symmetric_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except ValueError:
            self.output_label_decryption.config(text="Decryption failed: Invalid private key.", fg="red")
            return

        aesgcm = AESGCM(symmetric_key)
        try:
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
        except ValueError:
            self.output_label_decryption.config(text="Decryption failed: Invalid data.", fg="red")
            return

        if self.save_file(file_path, decrypted_data):
            self.output_label_decryption.config(text="File decrypted and saved successfully!", fg='green')
        else:
            self.output_label_decryption.config(text="Decryption failed: Failed to save file.", fg="red")

    def generate_key_from_password(self, password, salt=b"my_salt"):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def password_entry_decryption_click(self, event):
        if self.password_entry_decryption.get() == "Required**":
            self.password_entry_decryption.delete(0, tk.END)

    def password_entry_decryption_leave(self, event):
        if self.password_entry_decryption.get() == "":
            self.password_entry_decryption.insert(0, "Required**")

    def public_key_entry_decryption_click(self, event):
        if self.public_key_entry_decryption.get() == "Recipient's Public Key**":
            self.public_key_entry_decryption.delete(0, tk.END)

    def public_key_entry_decryption_leave(self, event):
        if self.public_key_entry_decryption.get() == "":
            self.public_key_entry_decryption.insert(0, "Recipient's Public Key**")

    def private_key_entry_decryption_click(self, event):
        if self.private_key_entry_decryption.get() == "Your Private Key**":
            self.private_key_entry_decryption.delete(0, tk.END)

    def private_key_entry_decryption_leave(self, event):
        if self.private_key_entry_decryption.get() == "":
            self.private_key_entry_decryption.insert(0, "Your Private Key**")



    def toggle_password_entry_decryption(self):
        if self.password_radio_var_decryption.get() == "password":
            self.password_entry_decryption.pack(padx=10, pady=5)
            self.public_key_entry_decryption.pack_forget()
            self.private_key_entry_decryption.pack_forget()
            self.show_password_checkbox_decryption.pack(padx=10, pady=5)
            self.decrypt_button.pack(padx=10, pady=5)
            self.decrypt_with_rsa_keys_button.pack_forget()
        else:
            self.password_entry_decryption.pack_forget()
            self.public_key_entry_decryption.pack(padx=10, pady=5)
            self.private_key_entry_decryption.pack(padx=10, pady=5)
            self.show_password_checkbox_decryption.pack_forget()
            self.decrypt_button.pack_forget()
            self.decrypt_with_rsa_keys_button.pack(padx=10, pady=5)

    def toggle_password_visibility_decryption(self):
        if self.show_password_var_decryption.get():
            self.password_entry_decryption.config(show="")
        else:
            self.password_entry_decryption.config(show="*")

    def clear_decrypt_fields(self):
        self.decrypt_file_entry.delete(0, tk.END)
        self.password_entry_decryption.delete(0, tk.END)
        self.public_key_entry_decryption.delete(0, tk.END)
        self.private_key_entry_decryption.delete(0, tk.END)
        self.output_label_decryption.config(text="")

        if not self.password_entry_decryption.get():
            self.password_entry_decryption.insert(0, "Required**")
        if not self.public_key_entry_decryption.get():
            self.public_key_entry_decryption.insert(0, "Recipient's Public Key**")
        if not self.private_key_entry_decryption.get():
            self.private_key_entry_decryption.insert(0, "Your Private Key**")
  