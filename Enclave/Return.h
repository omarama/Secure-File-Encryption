#pragma once
#include "sgx_trts.h"
#include <stdlib.h>
#include <stdio.h>    
#include <cstring>
#include "Encryption_Decryption.h"

sgx_status_t returnCipher(const EncryptedText &encrypted);
sgx_status_t returnPlain(const DecryptedText &decrypted);
sgx_status_t returnKey(uint8_t *output, int length);
sgx_status_t getKey(uint8_t *key, int length);