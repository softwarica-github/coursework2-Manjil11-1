import tkinter.ttk as ttk
import tkinter as tk
from home_gui import HomeGUI
from encryption_gui import EncryptionGUI
from decryption_gui import DecryptionGUI
from encdec_function import *


class SecureFileSystemApp:
    def __init__(self):
        # Create the main window
        self.window = tk.Tk()
        self.window.title("Secure File System")

        # Create a notebook widget
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill='both', expand=True)

        # Create the tabs
        self.home_section = HomeGUI(self.notebook)
        self.encryption_section = EncryptionGUI(self.notebook)
        self.decryption_section = DecryptionGUI(self.notebook)

        # Add the tabs to the notebook
        self.notebook.add(self.home_section, text='Home')
        self.notebook.add(self.encryption_section, text='Encrypt')
        self.notebook.add(self.decryption_section, text='Decrypt')


        self.exit_button = tk.Button(self.window, text="Exit", command=self.window.destroy)
        # self.exit_button.grid(row=3, column=2, padx=10, pady=10)
        self.exit_button.pack(side=tk.BOTTOM, padx=0, pady=10)

        # Run the GUI
        # self.window.protocol("WM_DELETE_WINDOW", self.close_windows)
        self.window.mainloop()

    # def close_windows(self):
    #     # Close the main window
    #     self.window.destroy()

if __name__ == "__main__":
    app = SecureFileSystemApp()

