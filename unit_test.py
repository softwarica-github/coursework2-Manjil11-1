import unittest
import tkinter as tk
import os
from unittest.mock import patch, MagicMock
from decryption_gui import DecryptionGUI
from unittest.mock import patch, MagicMock
from encryption_gui import EncryptionGUI
from encdec_function import EncDecFunction
from home_gui import HomeGUI
from tkinter import Tk
from tkinter.ttk import Label
import tkinter.font as font

class TestDecryptionGUI(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.decryption_gui = DecryptionGUI(self.root)

    def tearDown(self):
        self.root.update()  # Process any pending events
        self.decryption_gui.destroy()
        self.root.destroy()


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

        # Ensure the public key entry is visible when necessary
        if self.password_radio_var_decryption.get() == "password":
            self.public_key_entry_decryption.pack(padx=10, pady=5)


    def toggle_password_visibility_decryption(self):
        if self.show_password_var_decryption.get():
            self.password_entry_decryption.config(show="")
        else:
            self.password_entry_decryption.config(show="•")

    def test_clear_decrypt_fields(self):
        self.decryption_gui.decrypt_file_entry.insert(tk.END, "test_file.enc")
        self.decryption_gui.password_entry_decryption.insert(tk.END, "test_password")
        self.decryption_gui.public_key_entry_decryption.insert(tk.END, "test_public_key")
        self.decryption_gui.private_key_entry_decryption.insert(tk.END, "test_private_key")
        self.decryption_gui.output_label_decryption.config(text="Test message", fg="red")

        self.decryption_gui.clear_decrypt_fields()

        # Assert that all fields are cleared
        self.assertEqual(self.decryption_gui.decrypt_file_entry.get(), "")
        self.assertEqual(self.decryption_gui.password_entry_decryption.get(), "Required**")
        self.assertEqual(self.decryption_gui.public_key_entry_decryption.get(), "Recipient's Public Key**")
        self.assertEqual(self.decryption_gui.private_key_entry_decryption.get(), "Your Private Key**")
        self.assertEqual(self.decryption_gui.output_label_decryption.cget("text"), "")

    def test_decrypt_file_with_password(self):
        # Create a test file to decrypt
        test_file_path = "test_file.enc"
        test_data = b"encrypted_data"
        with open(test_file_path, "wb") as file:
            file.write(test_data)

        # Set the file path and password
        self.decryption_gui.decrypt_file_entry.insert(tk.END, test_file_path)
        self.decryption_gui.password_entry_decryption.insert(tk.END, "test_password")

        # Decrypt the file
        self.decryption_gui.decrypt_file_with_password()

        # Check if the file is decrypted and saved successfully
        self.assertTrue(os.path.isfile(test_file_path))
        with open(test_file_path, "rb") as file:
            decrypted_data = file.read()
        self.assertEqual(decrypted_data, test_data)

        # Clean up: Delete the test file
        os.remove(test_file_path) 

    def test_decrypt_file_with_rsa(self):
        # Create a test file to decrypt
        test_file_path = "test_file.enc"
        test_data = b"encrypted_data"
        with open(test_file_path, "wb") as file:
            file.write(test_data)

        # Set the file path and private key
        self.decryption_gui.decrypt_file_entry.insert(tk.END, test_file_path)
        self.decryption_gui.private_key_entry_decryption.insert(tk.END, "test_private_key")

        # Decrypt the file
        self.decryption_gui.decrypt_file_with_rsa()

        # Check if the file is decrypted and saved successfully
        self.assertTrue(os.path.isfile(test_file_path))
        with open(test_file_path, "rb") as file:
            decrypted_data = file.read()
        self.assertEqual(decrypted_data, test_data)

        # Clean up: Delete the test file
        os.remove(test_file_path)

class TestEncryptionGUI(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.encryption_gui = EncryptionGUI(self.root)

    def tearDown(self):
        self.root.update()  # Process any pending events
        self.encryption_gui.destroy()
        self.root.destroy()

    def test_generate_key_from_password(self):
        password = "test_password"
        key = self.encryption_gui.generate_key_from_password(password)
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 44)

    def test_clear_encrypt_file_entry(self):
        self.encryption_gui.clear_encrypt_file_entry()
        file_path = self.encryption_gui.file_entry.get()
        self.assertEqual(file_path, "")

    def test_generate_password(self):
        self.encryption_gui.generate_password()
        password = self.encryption_gui.password_entry.get()
        self.assertIsNotNone(password)
        self.assertNotEqual(password, "Required**")

    def test_clear_encrypt_fields(self):
        self.encryption_gui.clear_encrypt_fields()
        file_path = self.encryption_gui.file_entry.get()
        password = self.encryption_gui.password_entry.get()
        public_key = self.encryption_gui.public_key_entry.get()
        private_key = self.encryption_gui.private_key_entry.get()

        self.assertEqual(file_path, "")
        self.assertEqual(password, "Required**")
        self.assertEqual(public_key, "Recipient's Public Key**")
        self.assertEqual(private_key, "Your Private Key**")


    def test_encrypt_file_with_rsa_invalid_public_key(self):
        file_path = "test_file.txt"
        public_key_pem = "test_public_key"

        with patch("encryption_gui.open"):
            with patch("encryption_gui.serialization.load_pem_public_key", side_effect=ValueError("Invalid public key.")) as mock_load_public_key:
                self.encryption_gui.file_entry.delete(0, "end")
                self.encryption_gui.file_entry.insert(0, file_path)
                self.encryption_gui.public_key_entry.delete(0, "end")
                self.encryption_gui.public_key_entry.insert(0, public_key_pem)

                self.encryption_gui.encrypt_file_with_rsa()

                mock_load_public_key.assert_called_once_with(public_key_pem.encode())
                self.assertEqual(self.encryption_gui.output_label_encryption.cget("text"), "Invalid public key.")
                self.assertEqual(self.encryption_gui.output_label_encryption.cget("fg"), "red")


class TestEncDecFunction(unittest.TestCase):
    def setUp(self):
        self.enc_dec_function = EncDecFunction()

    def test_save_file(self):
        # Mock the filedialog.asksaveasfilename method
        with patch("encdec_function.filedialog.asksaveasfilename") as mock_asksaveasfilename:
            # Set the return value of mock_asksaveasfilename
            mock_asksaveasfilename.return_value = "test_file.enc"

            # Test saving a file with data
            data = b"test_data"
            file_path = "test_file.txt"
            saved = self.enc_dec_function.save_file(file_path, data)

            # Assert that filedialog.asksaveasfilename was called
            mock_asksaveasfilename.assert_called_once()

            # Assert that the file was saved
            self.assertTrue(saved)
            self.assertTrue(mock_asksaveasfilename.return_value, "test_file.enc")
            self.assertTrue(os.path.isfile("test_file.enc"))

            # Clean up: Delete the test file
            os.remove("test_file.enc")

    def test_generate_key_from_password(self):
        # Test generating a key from password
        password = "test_password"
        key = self.enc_dec_function.generate_key_from_password(password)

        # Assert that the key is generated successfully
        self.assertIsNotNone(key)

        # Assert that the key is bytes
        self.assertIsInstance(key, bytes)

        # Assert that the key length is 44 (base64 encoded)
        self.assertEqual(len(key), 44)


class TestHomeGUI(unittest.TestCase):
    def setUp(self):
        # Create a root window for testing
        self.root = Tk()

        # Create an instance of HomeGUI for each test case
        self.home_gui = HomeGUI(self.root)

    def tearDown(self):
        self.root.update()  # Process any pending events
        self.home_gui.destroy()
        self.root.destroy()


    def test_labels_text(self):
        self.assertIsInstance(self.home_gui.home_label, Label)
        self.assertEqual(self.home_gui.home_label.cget("text"), "About Secure File System")

        actual_font = font.Font(font=self.home_gui.home_label.cget("font"))
        actual_font_str = "-*-{family}-{weight}-{slant}-*-{size}-*-*-*-*-*-*-*".format(**actual_font.actual())
        self.assertEqual(actual_font_str, "-*-Didot-bold-roman-*-20-*-*-*-*-*-*-*")



        self.assertIsInstance(self.home_gui.description_label, Label)
        expected_text = """A secure file system is designed to protect sensitive and confidential 
            data from unauthorized access, modification, or disclosure. It incorporates various 
            security mechanisms and features to ensure the 
            confidentiality, integrity, and availability of files and 
            data stored within the system. Here are some key aspects of a secure file system:"""
        self.assertEqual(self.home_gui.description_label.cget("text"), expected_text.strip())



if __name__ == '__main__':
    unittest.main()