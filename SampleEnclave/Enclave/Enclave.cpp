#include <stdarg.h>
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

/*Struct for the decision of the current encryption/decryption process, if the cipher/plaintext will be returned*/
struct ManagementUnit
{
	bool encryption_decryption = false;						//is the encryption/decryption process successfull?
	bool logging = false;									//is the logging process successfull?
	bool policy = false;									//is the policy check process successfull?
};
/*Struct for the encryption process. The whole output data at the encrpytion is hold here.*/
struct EncryptedText
{
	uint8_t iv[12];						//holds the iv 
	uint8_t *cipher = nullptr;					//holds the output cipher
	sgx_aes_gcm_128bit_tag_t mac;		//holds the output mac
	int length_plain;					//holds the plaintext length
};
/*Struct for the decryption process. The whole output data  at the decryption is hold here*/
struct DecryptedText
{
	uint8_t iv[12];					//holds the iv
	uint8_t *plain = nullptr;					//holds the output plain text 
	sgx_aes_gcm_128bit_tag_t mac;	//holds the verification mac
	int length_cipher;				//holds the plaintext length 
};
#if 0
struct Key
{
	sgx_aes_gcm_128bit_key_t key;
	int key_length = sizeof(key);
};
#endif
/*Class for the encryption and decryption process.*/
class Crypt
{
private:
	sgx_aes_gcm_128bit_key_t groupAesKey;								//symmetric group key for all documents
public:
	/*Set symmetric key an initialization*/
	Crypt(const sgx_aes_gcm_128bit_key_t &aesKey)
	{
		memcpy(this->groupAesKey, aesKey, sizeof(this->groupAesKey));
	}
	/*
	Description:
	Decryption function. Generates an IV and decrypts the input plaintext. IV, length, mac and cipher will be saved in the &encrypted struct.
										Input:
	*plain			=		Pointer to the plaintext within the enclave memory region, which should be encrypted
	&encrypted		=		Pointer to the ciphertext struct within the enclave memory region, which stores all the necessary output data
										Output:
	ret				=		SGX_SUCCESS
					=		SGX_ERROR_INVALID_PARAMETER
					=		SGX_ERROR_OUT_OF_MEMORY
					=		SGX_ERROR_UNEXPECTED
	*/
	sgx_status_t secureEncrypt(const uint8_t *plain, EncryptedText &encrypted)
	{
		sgx_status_t ret = SGX_SUCCESS;																																			//return value
		sgx_read_rand((unsigned char *)encrypted.iv, sizeof(encrypted.iv));				//set iv value with random numbers
		ret = sgx_rijndael128GCM_encrypt(&groupAesKey, plain, encrypted.length_plain, encrypted.cipher, encrypted.iv, sizeof(encrypted.iv), NULL, 0, &encrypted.mac);			//encrypt
		return ret;
	}
	/*
	Description:
	Encryption function. Passes the iv,length,mac and cihper to the decryption function .
	If the mac verifcation is successfull the decrypted plaintext will be saved in the decrypted struct.
	Input:
	*cipher			=		Pointer to the cipher within the enclave memory region, which should be decrypted
	&encrypted		=		Pointer to the plaintext struct within the enclave memory region, which stores all the necessary decryptin data and the output plaintext
	Output:
	ret				=		SGX_SUCCESS
					=		SGX_ERROR_INVALID_PARAMETER
					=		SGX_ERROR_OUT_OF_MEMORY
					=		SGX_ERROR_UNEXPECTED
	*/
	sgx_status_t secureDecrypt(const uint8_t *cipher, DecryptedText &decrypted)
	{
		sgx_status_t ret = SGX_SUCCESS;																													//return value
		ret = sgx_rijndael128GCM_decrypt(&groupAesKey, cipher + 16, decrypted.length_cipher, decrypted.plain, decrypted.iv, sizeof(decrypted.iv), NULL, 0, &decrypted.mac);		//decrypt
		return ret;
	}
};
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
/*ECALL function for the encryption process.
						Input:
char *input			= whole input plaintext
size_t length		= length of the input
						Output:
At the moment sgx_status_t. Will be changed if the process is larger an own error handling is implemented.
res					= SGX_SUCCESS
*/
sgx_status_t ecall_AuditLoggingEnc_sample(char *input, size_t length)
{
	sgx_status_t res;																			//Error messages
	uint8_t *plain = (uint8_t *)malloc(length);													//memory for internal input
	EncryptedText encrypted;																	//decrypt struct with iv, mac and plain
	Key group_key; 																				//group key struct
	ManagementUnit manage;

	/*Initialization*/
	encrypted.length_plain = length;															//length of the cipher! Caution No padding because aes gcm
	/*Soll ich hier malloc anwenden oder im in der funktion encryptionBlock(..)*/
	encrypted.cipher = (uint8_t*)malloc(encrypted.length_plain);								//allocate memory for ciphertext output
	sgx_read_rand((unsigned char *)& group_key, sizeof(sgx_aes_gcm_128bit_key_t));				//generate random number within enclave for the Key. This is only used until TLS is implemented																	
	memcpy(plain, input, encrypted.length_plain);														//copy input into sgx memory space

	/*encryption sequence*/
	res = encryptionBlock(encrypted, plain, group_key);											//open encryption/decryption block and return success / unsuccess
	if (res != SGX_SUCCESS)																		//no success at encryption
	{
		printf("An error is occured during the encryption Block\n!");
		manage.encryption_decryption = false;													//set decision variable to false
	}
	else if (res == SGX_SUCCESS)																//success at the encryption 
	{
		manage.encryption_decryption = true;													//set the decision variable to true
	}
	/*Return the Cipher or Plaintext file*/
	if (manage.encryption_decryption == true)												//decide if the file will be returned
	{
		returnCipher(encrypted);															//return cipher 
		/*Only be used until TLS is implemented*/
		returnKey(group_key, 16);															//return key 
	}

	/*free dynamic memory*/
	free(plain);
	free(encrypted.cipher);
	return res;
}
/*ECALL function for the encryption process.
Input:
char *input			= whole input plaintext
size_t length		= length of the input
Output:
At the moment sgx_status_t. Will be changed if the process is larger an own error handling is implemented.
res					= SGX_SUCCESS
*/
sgx_status_t ecall_AuditLoggingDec_sample(char *input, size_t length)
{
	sgx_status_t res;																								//Error messages
	uint8_t *cipherinput = (uint8_t *)malloc(length);																	//memory for internal input
	DecryptedText decrypted;																						//decrypt struct with iv, mac and plain
	Key group_key;																								// symmetric group key
	ManagementUnit manage;																							//management unit decision

	/*Initialization*/
	decrypted.length_cipher = length - sizeof(decrypted.iv) - sizeof(decrypted.mac) - sizeof(decrypted.length_cipher); //length of the input - iv -mac - cipherlength (4byte)
	decrypted.plain = (uint8_t*)malloc(decrypted.length_cipher);													//allocate memory for plaintext output
	getKey(group_key, sizeof(group_key));																			//take key from untrusted 															
	memcpy(cipherinput, input, length);																						//copy input into sgx memory space

	/*encryption sequence*/
	res = decryptionBlock(decrypted, cipherinput, group_key);															//open decryption block
	if (res != SGX_SUCCESS)																							//No success at decryptin
	{
		printf("An error is occured during the decryption Block\n!");						
		manage.encryption_decryption = false;
	}
	else if (res == SGX_SUCCESS)																			//success at the decryption 
	{
		manage.encryption_decryption = true;																//set the decision variable to true
	}

	/*Return the Cipher or Plaintext file*/
	if (manage.encryption_decryption == true)
	{
		returnPlain(decrypted);
	}

	/*free dynamic memory*/
	free(cipherinput);
	free(decrypted.plain);
	return res;
}
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
	char * output = new char [sizeof(encrypted.length_plain) + sizeof(encrypted.cipher) + sizeof(encrypted.mac)+encrypted.length_plain];				//declare output array
	memcpy(output, &encrypted.length_plain, sizeof(encrypted.length_plain));																			//copy cipher length to the output
	memcpy(output + sizeof(encrypted.length_plain), encrypted.iv, sizeof(encrypted.iv));																//copy iv to the output
	memcpy(output + sizeof(encrypted.iv)+ sizeof(encrypted.length_plain), encrypted.cipher, encrypted.length_plain);									//copy cipher to the output
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
	char * output = new char[decrypted.length_cipher + sizeof(decrypted.plain) + sizeof(decrypted.mac)];					//declare output array
	memcpy(output, decrypted.plain, decrypted.length_cipher);																//copy plaintext to the output array
	ocall_return_plain((char*)output, decrypted.length_cipher);				//open ocall to return plaintext
	return ret;
}
/*Only used until TLS channel is not implemented*/
sgx_status_t returnKey(uint8_t *output, int length)
{
	sgx_status_t ret = SGX_SUCCESS;
	ocall_return_key((char*)output, length);
	return ret;
}
/*Get the Key from elsewhere. At the moment untrusted OS. Later TLS channel*/
sgx_status_t getKey(uint8_t *key, int length)
{
	sgx_status_t ret = SGX_SUCCESS;
	ocall_get_key((char*)key, length);
	return ret;
}
/*
Description:
Encryption Block. All necessary pre-work for the encryption and the encryption process itself will be executed here
										Input:
EncrpytedText &encpryted				= All output data will be stored here
const uint8_t *plain					= The input plaintext. 
const Key &group_key					= The symmetric group key
										Output:
sgx_status_t ret						= SGX_SUCCESS
*/
sgx_status_t encryptionBlock(EncryptedText &encrypted,const  uint8_t *plain, const Key &group_key)
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
const uint8_t *cipher					= The input cipher.
const Key &group_key					= The symmetric group key
Output:
sgx_status_t ret						= SGX_SUCCESS
*/
sgx_status_t decryptionBlock(DecryptedText &decrypted,const uint8_t *cipher, const Key &group_key)
{
	sgx_status_t ret=SGX_SUCCESS; 
	Crypt crypt(group_key);														//Cryption object with the Key and the decrpyption function
	memcpy(&decrypted.length_cipher, cipher , sizeof(decrypted.length_cipher));		//take the length from the cipher 
	memcpy(&decrypted.iv, cipher+sizeof(decrypted.length_cipher), sizeof(decrypted.iv));		//take the iv from the cipher 
	memcpy(&decrypted.mac, cipher + sizeof(decrypted.length_cipher) + sizeof(decrypted.iv) + decrypted.length_cipher, sizeof(decrypted.mac));		//take the mac from the cipher
	ret = crypt.secureDecrypt(cipher, decrypted);								//decrypt the cipher
	return ret;
}