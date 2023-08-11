import unittest
import tkinter.ttk as tk
from encdec_function import *
from unit_test import TestDecryptionGUI,TestEncryptionGUI,TestHomeGUI,TestEncDecFunction
from home_gui import HomeGUI
from home import SecureFileSystemApp
import subprocess
import os


if __name__ == "__main__":

    # Run the unittests
    suite = unittest.TestSuite()
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestDecryptionGUI))
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestEncDecFunction))
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestEncryptionGUI))
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestHomeGUI))
    runner = unittest.TextTestRunner(verbosity=2)
    test_result = runner.run(suite)

    if test_result.wasSuccessful():
    #     os.kill(os.getpid(), 9)

        os.system('killall -9 python')  # Be careful with this, it will kill all Python processes
        # os.system('python /Users/manzil/Desktop/Pr0t3ct-main/secure_file_system/home.py') 
        subprocess.run(['python', '/Users/manzil/Desktop/Pr0t3ct-main/secure_file_system/home.py'])



