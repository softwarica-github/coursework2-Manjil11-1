from encryption_gui import *

class EncDecFunction(ttk.Frame):
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
 