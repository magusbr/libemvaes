#ifndef __AES_EVP_INC__
#define __AES_EVP_INC__

typedef enum aes_evp_type
{
    AES_EVP_ENCRYPT = 0,
    AES_EVP_DECRYPT
} aes_evp_type;

int aes_evp_crypt(char* plaintext, char* ciphertext, const char* password, int enc_dec);


#endif // __AES_EVP_INC__
