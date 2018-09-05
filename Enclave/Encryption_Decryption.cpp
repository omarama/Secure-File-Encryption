#include "Encryption_Decryption.h"
#include "Enclave.h"
/*
Description:
Encryption Block. All necessary pre-work for the encryption and the encryption process itself will be executed here
Input:
EncrpytedText &encpryted				= All output data will be stored here
const std::vector<std::uint8_t> &plain	= The input plaintext.
const Key &group_key					= The symmetric group key
Output:
sgx_status_t ret						= SGX_SUCCESS
*/
sgx_status_t encryptionBlock(EncryptedText &encrypted, const std::vector<std::uint8_t> &plain, const Key &group_key)
{
	sgx_status_t ret;
	Crypt crypt(group_key);									//Cryption object with the Key and the encrpyption function 

	ret = crypt.secureEncrypt(plain, encrypted);					//encrypt the plaintext
	return ret;
}
/*
Description:
Decryption Block. All necessary pre-work for the decryption and the decryption process itself will be executed here
Input:
DecrpytedText &decpryted				= All output data will be stored here
const std::vector<uint8_t> &cipher					= The input cipher.
const Key &group_key					= The symmetric group key
Output:
sgx_status_t ret						= SGX_SUCCESS
*/
sgx_status_t decryptionBlock(DecryptedText &decrypted, const std::vector<std::uint8_t> &cipher, const Key &group_key)
{
	sgx_status_t ret = SGX_SUCCESS;
	Crypt crypt(group_key);														//Cryption object with the Key and the decrpyption function
	memcpy(&decrypted.length_cipher, &cipher[0], sizeof(decrypted.length_cipher));		//take the length from the cipher 
	memcpy(decrypted.iv, &cipher[sizeof(decrypted.length_cipher)], sizeof(decrypted.iv));		//take the iv from the cipher 
	memcpy(decrypted.mac, &cipher[sizeof(decrypted.length_cipher)] + sizeof(decrypted.iv) + decrypted.length_cipher, sizeof(decrypted.mac));		//take the mac from the cipher
	ret = crypt.secureDecrypt(cipher, decrypted);								//decrypt the cipher
	return ret;
}
/*
	Set symmetric key for any encryption / decryption purpose.
*/
Crypt::Crypt(const sgx_aes_gcm_128bit_key_t &aesKey)
{
	memcpy(this->groupAesKey, aesKey, sizeof(this->groupAesKey));
}
/*
Description:
Decryption function. Generates an IV and decrypts the input plaintext. IV, length, mac and cipher will be saved in the &encrypted struct.
											Input:
const std::vector<std::uint8_t> &plain		=		Pointer to the plaintext within the enclave memory region, which should be encrypted
EncryptedText &encrypted					=		Pointer to the ciphertext struct within the enclave memory region, which stores all the necessary output data
											Output:
ret											=		SGX_SUCCESS
											=		SGX_ERROR_INVALID_PARAMETER
											=		SGX_ERROR_OUT_OF_MEMORY
											=		SGX_ERROR_UNEXPECTED
*/
sgx_status_t Crypt::secureEncrypt(const std::vector<std::uint8_t> &plain, EncryptedText &encrypted)
{
	sgx_status_t ret = SGX_SUCCESS;																																									//return value
	sgx_read_rand(static_cast<unsigned char *>(encrypted.iv), sizeof(encrypted.iv));																												//set iv value with random numbers
	ret = sgx_rijndael128GCM_encrypt(&groupAesKey, plain.data(), encrypted.length_plain, encrypted.ciphertext.data(), encrypted.iv, sizeof(encrypted.iv), nullptr, 0, &encrypted.mac);				//encrypt
	return ret;
}
/*
Description:
Encryption function. Passes the iv,length,mac and cihper to the decryption function .
If the mac verifcation is successfull the decrypted plaintext will be saved in the decrypted struct.
											Input:
const std::vector<std::uint8_t> &cipher		=		Pointer to the cipher within the enclave memory region, which should be decrypted
DecryptedText &decrypted					=		Pointer to the plaintext struct within the enclave memory region, which stores all
													the necessary decryptin data and the output plaintext
											Output:
ret											=		SGX_SUCCESS
											=		SGX_ERROR_INVALID_PARAMETER
											=		SGX_ERROR_OUT_OF_MEMORY
											=		SGX_ERROR_UNEXPECTED
*/
sgx_status_t Crypt::secureDecrypt(const std::vector<std::uint8_t> &cipher, DecryptedText &decrypted)
{
	sgx_status_t ret = SGX_SUCCESS;																																								//return value
	ret = sgx_rijndael128GCM_decrypt(&groupAesKey, &cipher[sizeof(decrypted.length_cipher)+sizeof(decrypted.iv)], decrypted.length_cipher, decrypted.plaintext.data(), decrypted.iv, sizeof(decrypted.iv), nullptr, 0, &decrypted.mac);			//decrypt
	return ret;
}