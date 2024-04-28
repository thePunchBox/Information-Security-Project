import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

class FileEncryptorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("File Encryptor-IS Project")

        self.input_file_label = tk.Label(master, text="Input File:")
        self.input_file_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.input_file_entry = tk.Entry(master, width=50)
        self.input_file_entry.grid(row=0, column=1, padx=10, pady=5)
        self.input_file_button = tk.Button(master, text="Browse", command=self.browse_input_file)
        self.input_file_button.grid(row=0, column=2, padx=10, pady=5)

        self.output_folder_label = tk.Label(master, text="Output Folder:")
        self.output_folder_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.output_folder_entry = tk.Entry(master, width=50)
        self.output_folder_entry.grid(row=1, column=1, padx=10, pady=5)
        self.output_folder_button = tk.Button(master, text="Browse", command=self.browse_output_folder)
        self.output_folder_button.grid(row=1, column=2, padx=10, pady=5)

        self.algorithm_label = tk.Label(master, text="Encryption Algorithm:")
        self.algorithm_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.algorithms = ["AES", "3DES", "DES"]
        self.selected_algorithm = tk.StringVar()
        self.selected_algorithm.set(self.algorithms[0])  # Default to AES
        self.algorithm_menu = tk.OptionMenu(master, self.selected_algorithm, *self.algorithms)
        self.algorithm_menu.grid(row=2, column=1, padx=10, pady=5)

        self.generate_key_button = tk.Button(master, text="Generate Key", command=self.generate_key)
        self.generate_key_button.grid(row=3, column=0, columnspan=3, padx=10, pady=5)

        self.key_file_label = tk.Label(master, text="Key File:")
        self.key_file_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")
        self.key_file_entry = tk.Entry(master, width=50)
        self.key_file_entry.grid(row=4, column=1, padx=10, pady=5)
        self.key_file_button = tk.Button(master, text="Browse", command=self.browse_key_file)
        self.key_file_button.grid(row=4, column=2, padx=10, pady=5)

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=5, column=0, padx=10, pady=5)
        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=5, column=1, padx=10, pady=5)

        # Footer
        self.footer_label = tk.Label(master, text="21SW152, 21SW126, 21SW58", fg="gray")
        self.footer_label.grid(row=6, column=0, columnspan=3, padx=10, pady=5, sticky="se")

    def browse_input_file(self):
        filename = filedialog.askopenfilename()
        self.input_file_entry.delete(0, tk.END)
        self.input_file_entry.insert(0, filename)

    def browse_output_folder(self):
        foldername = filedialog.askdirectory()
        self.output_folder_entry.delete(0, tk.END)
        self.output_folder_entry.insert(0, foldername)

    def generate_key(self):
        key_algorithm = self.selected_algorithm.get()
        if key_algorithm == "AES":
            key = get_random_bytes(16)
        elif key_algorithm == "3DES":
            key = get_random_bytes(24)
        else:  # DES
            key = get_random_bytes(8)

        keys_folder = os.path.join(os.path.dirname(self.output_folder_entry.get()), "keys")
        os.makedirs(keys_folder, exist_ok=True)
        key_filename = os.path.join(keys_folder, f"{key_algorithm.lower()}_key.key")
        with open(key_filename, 'wb') as key_file:
            key_file.write(key)
        messagebox.showinfo("Key Generated", f"{key_algorithm} key generated and saved successfully!")

    def browse_key_file(self):
        filename = filedialog.askopenfilename()
        self.key_file_entry.delete(0, tk.END)
        self.key_file_entry.insert(0, filename)

    def encrypt(self):
        input_file = self.input_file_entry.get()
        output_folder = self.output_folder_entry.get()
        key_file = self.key_file_entry.get()
        algorithm = self.selected_algorithm.get()

        # Read the key from the key file
        with open(key_file, 'rb') as f:
            key = f.read()

        # Generate initialization vector (IV)
        iv = os.urandom(16) if algorithm == "AES" else os.urandom(8)

        # Create cipher object
        if algorithm == "AES":
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif algorithm == "3DES":
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
        else:
            cipher = DES.new(key, DES.MODE_CBC, iv)

        # Read input file contents
        with open(input_file, 'rb') as f:
            plaintext = f.read()

        # Encrypt the plaintext
        if algorithm == "AES" or algorithm == "3DES":
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        else:
            # For DES, pad with a multiple of 8 bytes
            ciphertext = cipher.encrypt(pad(plaintext, 8))

        # Write encrypted data to output file
        output_filename = f"{os.path.splitext(os.path.basename(input_file))[0]}_encrypted_using_{algorithm.lower()}.enc"
        output_file = os.path.join(output_folder, output_filename)
        with open(output_file, 'wb') as f:
            f.write(iv)
            f.write(ciphertext)

        messagebox.showinfo("Encryption Complete", "File encrypted successfully!")

    def decrypt(self):
        input_file = self.input_file_entry.get()
        output_folder = self.output_folder_entry.get()
        key_file = self.key_file_entry.get()
        algorithm = self.selected_algorithm.get()

        # Read the key from the key file
        with open(key_file, 'rb') as f:
            key = f.read()

        # Read the IV and ciphertext from the input file
        with open(input_file, 'rb') as f:
            iv = f.read(16) if algorithm == "AES" or algorithm == "3DES" else f.read(8)
            ciphertext = f.read()

        # Create cipher object
        if algorithm == "AES":
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif algorithm == "3DES":
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
        else:
            cipher = DES.new(key, DES.MODE_CBC, iv)

        # Decrypt the ciphertext
        if algorithm == "AES" or algorithm == "3DES":
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        else:
            plaintext = unpad(cipher.decrypt(ciphertext), 8)

        # Write decrypted data to output file
        output_filename = f"{os.path.splitext(os.path.basename(input_file))[0]}_decrypted_using_{algorithm.lower()}"
        output_file = os.path.join(output_folder, output_filename)
        with open(output_file, 'wb') as f:
            f.write(plaintext)

        messagebox.showinfo("Decryption Complete", "File decrypted successfully!")

def main():
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
