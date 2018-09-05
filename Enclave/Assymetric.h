#pragma once
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <vector>
#include <string>
/*
	The assymetric class is used to sign data with the private key. Furthermore it is used to 
	decrypt data if somebody sends you data encrypted with your public key.
*/
class Assymetric
{
private:
	sgx_ec256_private_t priv;
	sgx_ec256_public_t pub;
	sgx_ecc_state_handle_t ecc_handle;
public:
	Assymetric();
	~Assymetric();
	void setKeyPair();
	void setKeyPair(uint8_t priv[SGX_ECP256_KEY_SIZE * 3]);
	void sign(const std::string &input, sgx_ec256_signature_t &signature);
	bool verify(const std::string &input, sgx_ec256_signature_t &signature);
	void getPublic(sgx_ec256_public_t &pubKey);
	void getPubPriv(uint8_t keyPair[SGX_ECP256_KEY_SIZE*3]);
};