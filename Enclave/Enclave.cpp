#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

/*Struct for the decision of the current encryption/decryption process, if the cipher/plaintext will be returned*/
struct ManagementUnit
{
	bool encryption_decryption = false;						//is the encryption/decryption process successfull?
	bool logging = false;									//is the logging process successfull?
	bool policy = false;									//is the policy check process successfull?
};
#if 0
struct Key
{
	sgx_aes_gcm_128bit_key_t key;
	int key_length = sizeof(key);
};
#endif
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
sgx_status_t ecall_AuditLoggingEnc_sample(char *input, size_t length,char *fileName, int lengthFileName)
{
	sgx_status_t res;																			//Error messages
	EncryptedText encrypted;																	//decrypt struct with iv, mac and plain
	Key group_key; 																				//group key struct
	ManagementUnit manage;																		//managment unit
	std::string pathKeyPair= "../keyPair.txt";													//Path for the public and private key pair
	Document doc(input,length,fileName,lengthFileName,1);													//Initialize Document
	Assymetric assym;

	/*Start up configuration*/
	int keyPairSize = 0;							
	ocall_get_binary_file_size(pathKeyPair.c_str(), pathKeyPair.size(), &keyPairSize);			//Look if key pair is saved
	if (keyPairSize == 0)																		
	{
		assym.setKeyPair();																		//Key pair is not saved. Create new one	
		uint8_t keyPair[SGX_ECP256_KEY_SIZE * 3];
		assym.getPubPriv(keyPair);																
		seal::sealingBlock(*keyPair, SGX_ECP256_KEY_SIZE * 3,pathKeyPair);						//Key pair will be saved
		printf("The assymmetri key pair is generated and saved under the path:\n");
		for (int i = 0; i < pathKeyPair.size(); i++)
		{
			printf("%c", pathKeyPair[i]);
		}
		printf("\n");
	}																							//The Admin has to add the public key to the trusted ones at the server
	else
	{
		uint8_t keyPair[SGX_ECP256_KEY_SIZE*3];					
		ocall_get_binary((char*)keyPair, SGX_ECP256_KEY_SIZE * 3, pathKeyPair.c_str(), pathKeyPair.size());	//Key pair is saved. Read it and fill the object.
		assym.setKeyPair(keyPair);																			
	}

	/*Start Logging Block*/
	std::string loggingRecord;
	LoggingClient Log(doc);
	loggingRecord = Log.getLoggingRecord();

	/*Vorzeigezwecke*/
	printf("Der Logging Record is:\n");
	for (int i = 0; i < loggingRecord.size(); i++)
	{
		printf("%c", loggingRecord[i]);
	}
	printf("\n");

	/*encryption sequence*/
	encrypted.length_plain = doc.getFileSize();
	sgx_read_rand(static_cast<unsigned char*>(group_key), sizeof(group_key));				//generate random number within enclave for the Key. This is only used until TLS is implemented																	
	encrypted.ciphertext.reserve(encrypted.length_plain);
	res = encryptionBlock(encrypted, doc.getText(), group_key);											//open encryption/decryption block and return success / unsuccess
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
		returnKey(group_key, sizeof(group_key));															//return key 
	}	
	/*free dynamic memory*/
	return res;

	/*Not used*/
	//	std::vector<uint8_t> unsealed;
	//	std::string pathKey = "../sealed.txt";
	//	sgx_ec256_signature_t signature;
	//	seal::sealingBlock(plain, pathKey);
	//	seal::unsealingBlock(pathKey, unsealed);
	//std::string text;
	//text.insert(text.begin(), input, input + length);
	//	assym.sign(text, signature);
	//	assym.verify(text, signature);
}
/*ECALL function for the encryption process.
Input:
char *input			= whole input plaintext
size_t length		= length of the input
Output:
At the moment sgx_status_t. Will be changed if the process is larger an own error handling is implemented.
res					= SGX_SUCCESS
*/
sgx_status_t ecall_AuditLoggingDec_sample(char *input, size_t length, char *fileName, int lengthFileName)
{
	sgx_status_t res;																								//Error messages
	DecryptedText decrypted;																						//decrypt struct with iv, mac and plain
	Key group_key;																								// symmetric group key
	ManagementUnit manage;																							//management unit decision
	std::vector < uint8_t> cipherinput;
	std::string pathKeyPair = "../keyPair.txt";													//Path for the public and private key pair
	Document doc(input, length, fileName, lengthFileName, 0);													//Initialize Document
	Assymetric assym;

	/*Start up configuration*/
	int keyPairSize = 0;
	ocall_get_binary_file_size(pathKeyPair.c_str(), pathKeyPair.size(), &keyPairSize);			//Look if key pair is saved
	if (keyPairSize == 0)
	{
		assym.setKeyPair();																		//Key pair is not saved. Create new one	
		uint8_t keyPair[SGX_ECP256_KEY_SIZE * 3];
		assym.getPubPriv(keyPair);
		seal::sealingBlock(*keyPair, SGX_ECP256_KEY_SIZE * 3, pathKeyPair);						//Key pair will be saved
		printf("The assymmetri key pair is generated and saved under the path:\n");
		for (int i = 0; i < pathKeyPair.size(); i++)
		{
			printf("%c", pathKeyPair[i]);
		}
		printf("\n");
	}																							//The Admin has to add the public key to the trusted ones at the server
	else
	{
		uint8_t keyPair[SGX_ECP256_KEY_SIZE * 3];
		ocall_get_binary((char*)keyPair, SGX_ECP256_KEY_SIZE * 3, pathKeyPair.c_str(), pathKeyPair.size());	//Key pair is saved. Read it and fill the object.
		assym.setKeyPair(keyPair);
	}

	/*Start Logging Block*/
	std::string loggingRecord;
	LoggingClient Log(doc);
	loggingRecord = Log.getLoggingRecord();

	/*encryption sequence*/
	decrypted.length_cipher = length - sizeof(decrypted.iv) - sizeof(decrypted.mac) - sizeof(decrypted.length_cipher); //length of the input - iv -mac - cipherlength (4byte)
	getKey(group_key, sizeof(group_key));																			//take key from untrusted 															
	cipherinput.reserve(length);
	cipherinput.insert(cipherinput.begin(), input, input + cipherinput.capacity());											//copy input into sgx memory space
	decrypted.plaintext.reserve(length - sizeof(decrypted.iv) - sizeof(decrypted.mac) - sizeof(decrypted.length_cipher));
	res = decryptionBlock(decrypted, doc.getText(), group_key);															//open decryption block
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
	return res;
}
