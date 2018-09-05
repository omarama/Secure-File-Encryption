#pragma once
#include "Encryption_Decryption.h"				//Encryption/Deecryption Block
#include "Return.h"								//Return Block
#include "LoggingClient.h"
#include "Sealing.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <stdlib.h>
#include <stdio.h>    
#include <cstring>
#include <vector>
#include "Assymetric.h"

struct ManagementUnit;
using Key = sgx_aes_gcm_128bit_key_t;

#if defined(__cplusplus)
extern "C" {
#endif
void printf(const char *fmt, ...);
sgx_status_t ecall_AuditLoggingEnc_sample(char *output, size_t length,  char *fileName, int lengthFileName);
sgx_status_t ecall_AuditLoggingDec_sample(char *input, size_t length,  char *fileName, int lengthFileName);
#if defined(__cplusplus)
}
#endif


