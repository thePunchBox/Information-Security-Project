# Information-Security-Project

This is a simple file encryption tool developed as part of an Information Security project. It allows users to encrypt and decrypt files using different encryption algorithms such as AES, 3DES, and DES.

## Getting Started

To use the File Encryptor, follow these steps:

1. Clone the repository to your local machine.
2. Make sure you have Python installed.
3. Install the required dependencies using the following command:

```pip install pycryptodome```


4. Create the following empty folders within the project directory:
- `encrypted`: This folder will contain the encrypted files.
- `decrypted`: This folder will contain the decrypted files.
- `plain`: This folder will contain the plain text files to be encrypted.

5. Place the text files you want to encrypt in the `plain` folder.

6. Run the script `file_encryptor.py` to launch the application.

## Functionality

### 1. Browse Input File

- **Description:** Allows the user to select the file they want to encrypt or decrypt.
- **Usage:** Click the "Browse" button next to the "Input File" label, and select the desired file from the file dialog.

### 2. Browse Output Folder

- **Description:** Allows the user to choose the folder where the encrypted or decrypted file will be saved.
- **Usage:** Click the "Browse" button next to the "Output Folder" label, and select the desired folder from the directory dialog.

### 3. Encryption Algorithm Selection

- **Description:** Allows the user to choose the encryption algorithm to be used for encryption and decryption.
- **Usage:** Select the desired encryption algorithm from the dropdown menu labeled "Encryption Algorithm".

### 4. Generate Key

- **Description:** Generates a random key for the selected encryption algorithm and saves it to a file.
- **Usage:** Click the "Generate Key" button. The generated key will be saved in a 'keys' folder within the output folder.

### 5. Browse Key File

- **Description:** Allows the user to select the key file required for encryption or decryption.
- **Usage:** Click the "Browse" button next to the "Key File" label, and select the desired key file from the file dialog.

### 6. Encrypt

- **Description:** Encrypts the selected input file using the chosen encryption algorithm and saves the encrypted file to the specified output folder.
- **Usage:** Click the "Encrypt" button.

### 7. Decrypt

- **Description:** Decrypts the selected input file using the chosen encryption algorithm and saves the decrypted file to the specified output folder.
- **Usage:** Click the "Decrypt" button.

## Key Sizes

- **AES (Advanced Encryption Standard):** 128-bit key
- **3DES (Triple DES):** 168-bit key
- **DES (Data Encryption Standard):** 56-bit key

## Contributors

- 21SW152-Rafay Shakeel
- 21SW126-Mussawir Hussain
- 21SW038-Zohaib Khoso
