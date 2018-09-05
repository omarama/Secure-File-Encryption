#include "Sealing.h"
#include "Enclave_t.h"
#include "Enclave.h"

namespace seal 
{
	/*	Description: The sealing function is used to seal a file. This means the input will be encrypted 
		with an symmetric key which is only known by the enclave. Only the enclave can generate the key. 
		The input will be saved at the passed path. 
		Input: 
			const std::vector<uint8_t> &in		=	Input vector variable
			const std::string &path				=	Passed saved path
		Output:
			none	
	*/
	sgx_status_t sealingBlock(const std::vector<uint8_t> &in, const std::string &path)
	{
		sgx_status_t res=SGX_SUCCESS;
		uint32_t ciph_size = sgx_calc_sealed_data_size(0, in.size());
		char* sealed = (char*)malloc(ciph_size);
//
		if (sgx_is_within_enclave(in.data(),in.size()))								//Is the address within the prm?
		{
			res = sgx_seal_data(0, NULL, in.size(), in.data(), ciph_size, (sgx_sealed_data_t*)sealed);
			//		res = sgx_seal_data(0, NULL, lengthInput, &input, ciph_size, &output);
			ocall_write_binary(sealed, ciph_size, path.c_str(), path.size());
			//unsealingBlock(path, lengthPath);
			printf("File sealed!\n");
		}
		else
		{
			printf("Sealing memory not in PRM storage!\n");
		}
		return res;
	}
	sgx_status_t sealingBlock(const uint8_t &in, int lengthIn, const std::string &path)
	{
		sgx_status_t res = SGX_SUCCESS;
		uint32_t ciph_size = sgx_calc_sealed_data_size(0, lengthIn);
		char* sealed = (char*)malloc(ciph_size);
		if (sgx_is_within_enclave(&in, lengthIn))								//Is the address within the prm?
		{
			res = sgx_seal_data(0, NULL, lengthIn, &in, ciph_size, (sgx_sealed_data_t*)sealed);
			//		res = sgx_seal_data(0, NULL, lengthInput, &input, ciph_size, &output);
			ocall_write_binary(sealed, ciph_size, path.c_str(), path.size());
			//unsealingBlock(path, lengthPath);
			printf("File sealed!\n");
		}
		else
		{
			printf("Sealing memory not in PRM storage!\n");
		}
		return res;
	}
	/*	Description: The unsealing function is used to unseal a file. This means the input will be decrypted
	with an symmetric key which is only known by the enclave. Only the enclave can generate the key.
	The output will be stored in the unsealed vector variable.
	Input:
	const std::string &path					=	Where is the file
	std::vector<std::uint8_t> &unsealed		=	decrypted output variable
	Output:
	none
	*/
	sgx_status_t unsealingBlock(const std::string &path, std::vector<std::uint8_t> &unsealed)
	{
		sgx_status_t res = SGX_SUCCESS;
		int lengthSealed = 0;
		sgx_sealed_data_t *input;				//Warum geht das nicht?
		uint32_t plain_size = 0;
		uint8_t *out;
		ocall_get_binary_file_size(path.c_str(), path.size(), &lengthSealed);
		std::vector<char> seal;
		seal.reserve(lengthSealed);

		ocall_get_binary(seal.data(), lengthSealed, path.c_str(), path.size());
		plain_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t*) seal.data());
		out = new uint8_t[plain_size];
		unsealed.reserve(plain_size);
		if (sgx_is_within_enclave(seal.data(), lengthSealed))
		{
			res = sgx_unseal_data((sgx_sealed_data_t*) seal.data(), NULL, NULL, out, &plain_size);
			if (res == SGX_SUCCESS)
			{
				printf("The unsealed file is: \n");
				for (uint8_t i = 0; i < plain_size; i++)
				{
					printf("%c", out[i]);
				}
				unsealed.reserve(plain_size);
				unsealed.insert(unsealed.begin(), out, out + plain_size);
			}
			else
			{
				printf("It is not possible to unseal the file!\n");
			}
		}
		return res;
	}
}