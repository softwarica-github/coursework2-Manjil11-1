
import tkinter.ttk as tk
import tkinter.ttk as ttk
class HomeGUI(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)

        self.home_label = tk.Label(self, text="About Secure File System", font='didot 20 bold')
        self.home_label.pack(padx=5, pady=5)

        self.description_label = tk.Label(
            self,
            text="""A secure file system is designed to protect sensitive and confidential 
            data from unauthorized access, modification, or disclosure. It incorporates various 
            security mechanisms and features to ensure the 
            confidentiality, integrity, and availability of files and 
            data stored within the system. Here are some key aspects of a secure file system:"""
        )
        self.description_label.pack(padx=5, pady=5)
        self.pack()
           
