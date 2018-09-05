#include "Assymetric.h"


Assymetric::Assymetric(void)
{
	sgx_ecc256_open_context(&this->ecc_handle);
}
Assymetric::~Assymetric()
{
	sgx_ecc256_close_context(this->ecc_handle);
}
void Assymetric::setKeyPair()
{
	sgx_ecc256_create_key_pair(&this->priv, &this->pub, this->ecc_handle);
}
void Assymetric::setKeyPair(uint8_t priv[SGX_ECP256_KEY_SIZE * 3])
{
	memcpy(this->priv.r, priv, 32);
	memcpy(this->pub.gx, priv + 32, 32);
	memcpy(this->pub.gy, priv + 64, 32);
}
void Assymetric::sign(const std::string &input, sgx_ec256_signature_t &signature)
{
	sgx_status_t res = SGX_SUCCESS;
	uint8_t *in = new uint8_t[input.size()];
	memcpy(in, input.c_str(), input.size());
	res = sgx_ecdsa_sign(in, sizeof(in), &this->priv, &signature, this->ecc_handle);
	delete[] in;
	return;
}
bool Assymetric::verify(const std::string &input, sgx_ec256_signature_t &signature)
{
	sgx_status_t res = SGX_SUCCESS;
	uint8_t *in = new uint8_t[input.size()];
	memcpy(in, input.c_str(), input.size());
	uint8_t result[1];
	res = sgx_ecdsa_verify(in, sizeof(in), &this->pub, &signature, result, this->ecc_handle);
	delete[] in;
	if (result[0] == SGX_EC_VALID)
	{
		return true;
	}
	else
	{
		return false;
	}
}
void Assymetric::getPublic(sgx_ec256_public_t &pubKey)
{
	memcpy(&pubKey, &this->pub, 32);
	return;
}
void Assymetric::getPubPriv(uint8_t keyPair[SGX_ECP256_KEY_SIZE * 3])
{
	memcpy(keyPair, &this->priv, SGX_ECP256_KEY_SIZE);
	memcpy(keyPair, &this->pub, SGX_ECP256_KEY_SIZE*2);

}