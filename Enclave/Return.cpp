#include "Return.h"
#include "Enclave_t.h"

/*
Return the Cipherfile
Description:
Assemble the output file. First 4 bytes are the length of the plaintext. Thereafter 12 bytes of iv and than the  ciphertext of the plaintext file. At the end the mac with 16 bytes.
Input:
const EncryptedText &encrpyted	= All necessary data for the output file
Output:
sgx_status_t ret				=SGX_SUCCESS		Will be modified.

*/
sgx_status_t returnCipher(const EncryptedText &encrypted)
{
	sgx_status_t ret = SGX_SUCCESS;
	char * output = new char[sizeof(encrypted.iv) + sizeof(encrypted.length_plain) + encrypted.length_plain + sizeof(encrypted.mac)];				//declare output array
	memcpy(output, &encrypted.length_plain, sizeof(encrypted.length_plain));																			//copy cipher length to the output
	memcpy(output + sizeof(encrypted.length_plain), encrypted.iv, sizeof(encrypted.iv));																//copy iv to the output
	memcpy(output + sizeof(encrypted.iv) + sizeof(encrypted.length_plain), encrypted.ciphertext.data(), encrypted.length_plain);									//copy cipher to the output
	memcpy(output + sizeof(encrypted.iv) + sizeof(encrypted.length_plain) + encrypted.length_plain, encrypted.mac, sizeof(encrypted.mac));				//copy macto the output
	ocall_return_file(output, sizeof(encrypted.iv) + sizeof(encrypted.length_plain) + encrypted.length_plain + sizeof(encrypted.mac));					//open ocall function to return ciphertext
	return ret;
}
/*
Return the plaintext file
Description :
Assemble the output file with the plaintext
Input :
const DecryptedText &decrpyted = plaintext
Output :
sgx_status_t ret = SGX_SUCCESS		Will be modified.

*/
sgx_status_t returnPlain(const DecryptedText &decrypted)
{
	sgx_status_t ret = SGX_SUCCESS;
	char * output = new char[decrypted.length_cipher];					//declare output array
	memcpy(output, decrypted.plaintext.data(), decrypted.length_cipher);																//copy plaintext to the output array
	ocall_return_plain(output, decrypted.length_cipher);				//open ocall to return plaintext
	return ret;
}
/*Only used until TLS channel is not implemented*/
sgx_status_t returnKey(uint8_t *output, int length)
{
	sgx_status_t ret = SGX_SUCCESS;
	ocall_return_key(reinterpret_cast<char*>(output), length);			//extreme caution!
	return ret;
}
/*Get the Key from elsewhere. At the moment untrusted OS. Later TLS channel*/
sgx_status_t getKey(uint8_t *key, int length)
{
	sgx_status_t ret = SGX_SUCCESS;
	ocall_get_key(reinterpret_cast<char*>(key), length);						//extreme caution!
	return ret;
}
