#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>      /* vsnprintf */
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include <cstring>
#include <math.h>
#if defined(__cplusplus)
extern "C" {
#endif
struct EncryptedText;
struct DecryptedText;
struct ManagementUnit;
using Key = sgx_aes_gcm_128bit_key_t;
void printf(const char *fmt, ...);
sgx_status_t ecall_AuditLoggingEnc_sample(char *output, size_t length);
sgx_status_t ecall_AuditLoggingDec_sample(char *input, size_t length);
sgx_status_t returnCipher(const EncryptedText &encrypted);
sgx_status_t returnPlain(const DecryptedText &decrypted);
sgx_status_t returnKey(uint8_t *output, int length);
sgx_status_t getKey(uint8_t *key, int length);
sgx_status_t encryptionBlock(EncryptedText &encrypted,const uint8_t *text, const Key &group_key);
sgx_status_t decryptionBlock(DecryptedText &decrypted,const uint8_t *cipher, const Key &group_key);
#if defined(__cplusplus)
}
#endif
#endif /* !_ENCLAVE_H_ */
