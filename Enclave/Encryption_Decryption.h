#pragma once
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <stdlib.h>
#include <stdio.h>    
#include <cstring>
#include <vector>

using Key = sgx_aes_gcm_128bit_key_t;
/*Struct for the decryption process. The whole output data  at the decryption is hold here*/
struct DecryptedText
{
	uint8_t iv[12];					//holds the iv
	std::vector<uint8_t> plaintext;
	sgx_aes_gcm_128bit_tag_t mac;	//holds the verification mac
	int length_cipher;				//holds the plaintext length 
};
/*Struct for the encryption process. The whole output data at the encrpytion is hold here.*/
struct EncryptedText
{
	uint8_t iv[12];						//holds the iv 
	std::vector<uint8_t> ciphertext;
	sgx_aes_gcm_128bit_tag_t mac;		//holds the output mac
	int length_plain;					//holds the plaintext length
};
/*
	Encrypt the &text variable with the group key and output the &encrpyted struct, containing 
	the cihpertext. 
*/
sgx_status_t encryptionBlock(EncryptedText &encrypted, const std::vector<std::uint8_t> &text, const Key &group_key);
/*
	Decrypt the &text variable with the group key and output the &encrpyted struct, containing
	the cihpertext.
*/
sgx_status_t decryptionBlock(DecryptedText &decrypted, const std::vector<std::uint8_t> &cipher, const Key &group_key);
/*Class for the encryption and decryption process.*/
class Crypt
{
private:
	sgx_aes_gcm_128bit_key_t groupAesKey;								//symmetric group key for all documents
public:
	/*Set symmetric key an initialization*/
	Crypt(const sgx_aes_gcm_128bit_key_t &aesKey);
	sgx_status_t secureEncrypt(const std::vector<std::uint8_t> &plain, EncryptedText &encrypted);
	sgx_status_t secureDecrypt(const std::vector<std::uint8_t> &cipher, DecryptedText &decrypted);
};