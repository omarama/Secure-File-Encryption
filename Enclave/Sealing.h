#pragma once
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include <stdlib.h>
#include <stdio.h>    
#include <cstring>
#include<vector>

/*
	The seal namespace is used to seal and unseal data on the hard disk. 
	the encryption / decryption key is generated within the CPU from the enclave. 
*/
namespace seal
{
	sgx_status_t sealingBlock(const std::vector<uint8_t> &in, const std::string &path);
	sgx_status_t sealingBlock(const uint8_t &in, int lengthIn, const std::string &path);
	sgx_status_t unsealingBlock(const std::string &path, std::vector<std::uint8_t> &unsealed);
}