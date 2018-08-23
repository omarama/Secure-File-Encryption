# Secure-File-Encryption
File Encryption secured with Intel SGX


This Projekt encrypts a text file and within the Debug Path. The Cipher file and at the end the decrypted cipher file will be 
stored at the Debut Path as well. This is provisional and has to be developed in the future.

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

At the moment there is one class called 
crypt. This class stores the symmetric key. At the moment the symmetric key is unprotected but will be 
implemented in a secure way soon. 
The crypt class has two functions. 
1. secureEncrypt
2. secureDecrypt

Furthermore the 
