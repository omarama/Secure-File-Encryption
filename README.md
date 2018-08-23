p# Secure-File-Encryption
File Encryption secured with Intel SGX


This Projekt encrypts a text file and stores it within your project path as cipher.ctxt. 
After that this generated file will be red and decrypted again and stored in your project file as plain.txt.

This is the process:
1. Within the main a txt file is red
2. Initialize a enclave
3. Ecall the encryption process
4. Encrypt the file
5. Return the cipherfile as a ocall an store it within the untrusted system
6. Destroy the enclave
7. Read the cipherfile
8. Create an enclave
9. Ecall the decryption process
10. Decrypt the file
11. Return the plaintext file as a ocall an store it within the untrusted system
12. Destroy the encalve and clean everything

At the moment there is one class called crypt. This class stores the symmetric key. This key is unprotected but will be implemented in a secure way, soon.  
The crypt class has two functions. 
1. secureEncrypt
2. secureDecrypt

Furthermore the three structs are implemented. 
ManagementUnit: This is the central unit and has boolean variables. If the encryption is successful the 
variable is set to true. The planned logging and policy will be considered as well. 
EncryptedText/DecryptedText: The output of the enclave process.
