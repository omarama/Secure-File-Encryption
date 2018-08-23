#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <string>

#ifdef _MSC_VER
# include <Shlobj.h>
#else
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#endif

#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "App.h"
#include "Enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;
/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};
/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}
/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
#ifdef _MSC_VER
    /* try to get the token saved in CSIDL_LOCAL_APPDATA */
    if (S_OK != SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, token_path)) {
        strncpy_s(token_path, _countof(token_path), TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    } else {
        strncat_s(token_path, _countof(token_path), "\\" TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+2);
    }

    /* open the token file */
    HANDLE token_handler = CreateFileA(token_path, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
    if (token_handler == INVALID_HANDLE_VALUE) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    } else {
        /* read the token from saved file */
        DWORD read_num = 0;
        ReadFile(token_handler, token, sizeof(sgx_launch_token_t), &read_num, NULL);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
#else /* __GNUC__ */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
#endif
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
#ifdef _MSC_VER
        if (token_handler != INVALID_HANDLE_VALUE)
            CloseHandle(token_handler);
#else
        if (fp != NULL) fclose(fp);
#endif
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
#ifdef _MSC_VER
    if (updated == FALSE || token_handler == INVALID_HANDLE_VALUE) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (token_handler != INVALID_HANDLE_VALUE)
            CloseHandle(token_handler);
        return 0;
    }
    
    /* flush the file cache */
    FlushFileBuffers(token_handler);
    /* set access offset to the begin of the file */
    SetFilePointer(token_handler, 0, NULL, FILE_BEGIN);

    /* write back the token */
    DWORD write_num = 0;
    WriteFile(token_handler, token, sizeof(sgx_launch_token_t), &write_num, NULL);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    CloseHandle(token_handler);
#else /* __GNUC__ */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
#endif
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}
void ocall_return_file(char *file, int output_length)
{
	printf("The whole cipher in uint8 is:\n");
	for (int i = 0; i < output_length;i++)
	{
		printf("%hhu\t", file[i]);
	}
	printf("\nThe first 4 bytes are the length. The next 12 bytes are the IV and than comes the ciphertext with the described length. At the end the mac has a length of 16 bytes\n");
	std::ofstream output("../cipher.ctxt",std::ios::binary);
	if (output.is_open())
	{
		output.write(file, output_length);
		output.close();
	}
	return;
}
void ocall_return_plain(char *file, int output_length)
{
	printf("\nThe cipherfile is decrypted and the output is\n");
	for (int i = 0; i < output_length;i++)
	{
		printf("%c", file[i]);
	}
	printf("\nIt is saved at ${YourProjectPath}/SampleEnclave/plain.txt.\n");
	std::ofstream output("../plain.txt");
	if (output.is_open())
	{
		output.write(file, output_length);
		output.close();
	}
	return;
}
void ocall_get_key(char *file, int key_length)
{
	std::ifstream input("key.txt");
	if (input.is_open())
	{
		input.read(file, key_length);
		input.close();
	}
	return;
}
void ocall_return_key(char *file, int key_length)
{
	std::ofstream output("key.txt");
	if (output.is_open())
	{
		output.write(file, key_length);
		output.close();
	}
	return;
}

#if defined(_MSC_VER)
/* query and enable SGX device*/
int query_sgx_status()
{
    sgx_device_status_t sgx_device_status;
    sgx_status_t sgx_ret = sgx_enable_device(&sgx_device_status);
    if (sgx_ret != SGX_SUCCESS) {
        printf("Failed to get SGX device status.\n");
        return -1;
    }
    else {
        switch (sgx_device_status) {
        case SGX_ENABLED:
            return 0;
        case SGX_DISABLED_REBOOT_REQUIRED:
            printf("SGX device has been enabled. Please reboot your machine.\n");
            return -1;
        case SGX_DISABLED_LEGACY_OS:
            printf("SGX device can't be enabled on an OS that doesn't support EFI interface.\n");
            return -1;
        case SGX_DISABLED:
            printf("SGX is not enabled on this platform. More details are unavailable.\n");
            return -1;
        case SGX_DISABLED_SCI_AVAILABLE:
            printf("SGX device can be enabled by a Software Control Interface.\n");
            return -1;
        case SGX_DISABLED_MANUAL_ENABLE:
            printf("SGX device can be enabled manually in the BIOS setup.\n");
            return -1;
        case SGX_DISABLED_HYPERV_ENABLED:
            printf("Detected an unsupported version of Windows* 10 with Hyper-V enabled.\n");
            return -1;
        case SGX_DISABLED_UNSUPPORTED_CPU:
            printf("SGX is not supported by this CPU.\n");
            return -1;
        default:
            printf("Unexpected error.\n");
            return -1;
        }
    }
}
#endif

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
	sgx_status_t ret = SGX_SUCCESS;
#if defined(_MSC_VER)
    if (query_sgx_status() < 0) {
        /* either SGX is disabled, or a reboot is required to enable SGX */
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
#endif 
	/*Read File for encryption input*/
	char * text;
	int file_length;
	std::ifstream input("../test.txt");
	if (input.is_open())
	{
		int begin = input.tellg();										//first position
		input.seekg(0, std::ios::end);									//go to std::ios::end position
		int end = input.tellg();										//last position
		file_length = end - begin;									//get the file length
		input.seekg(0);													//go back to first position
		text = new char[file_length];
		input.read(text, file_length);
		input.close();
		printf("The file text.txt within the path ${YourProjectPath}/SampleEnclave was read.\n");
		for (int i = 0; i < file_length;i++)
		{
			printf("%c",text[i]);
		}
		printf("\n");
	}
	else
	{
		printf("The file cannot be opened!\n");
		return 0;
	}

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
	sgx_status_t ecall_ret = SGX_SUCCESS;

	/*Start the encryption process via the ecall function*/
	printf("The encrpytion process starts!\n");
	ret = ecall_AuditLoggingEnc_sample(global_eid, &ecall_ret, text, file_length);

	/*Clean everything*/
	file_length = 0;
	free(text);
	/* Destroy the enclave */
	sgx_destroy_enclave(global_eid);
	global_eid = 0;

	/*Read the file for the decryption process*/
	std::ifstream inputCipher("../cipher.ctxt", std::ios::binary);  //caution cipher is a binary
	if (inputCipher.is_open())
	{
		int begin = inputCipher.tellg();										//first position
		inputCipher.seekg(0, std::ios::end);									//go to std::ios::end position
		int end = inputCipher.tellg();											//last position
		file_length = end - begin;												//get the file length
		inputCipher.seekg(0);													//go back to the beginning
		text = new char[file_length];											//declare the size of the binary file as an array					
		inputCipher.read(text, file_length);									//read binary file
		inputCipher.close();													//close file
	}
	else
	{
		printf("The file cannot be opened!\n");
		return 0;
	}
	
	/* Initialize the enclave */
	if (initialize_enclave() < 0) {
		printf("Enter a character before exit ...\n");
		getchar();
		return -1;
	}

	/*Start decryption process*/
	ret = ecall_AuditLoggingDec_sample(global_eid, &ecall_ret, text, file_length);

//    /* Utilize edger8r attributes */
/*    edger8r_array_attributes();
//    edger8r_pointer_attributes();
//    edger8r_type_attributes();
//    edger8r_function_attributes();*/
//    
//    /* Utilize trusted libraries */
/*    ecall_libc_functions();
//    ecall_libcxx_functions();
//    ecall_thread_functions();*/

	/*Dealocate all dynamic memory*/
	free(text);
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Enter a character before exit ...\n");
    getchar();

    return 0;
}

