#ifndef __AES_EVP_INC__
#define __AES_EVP_INC__

typedef enum aes_evp_type
{
    AES_EVP_ENCRYPT = 0,
    AES_EVP_DECRYPT
} aes_evp_type;

int pass_to_key(unsigned char* key, unsigned char* iv, unsigned char* salt, unsigned char* password);
int aes_evp_cipher_add_salt(unsigned char* cipher, int* size, char* salt);
int aes_evp_crypt(char* plaintext, char* ciphertext, const char* password, int enc_dec);


int aes_crypt_large_error();
int aes_crypt_large_init(char* plaintext, char* ciphertext, const char* password);
int aes_crypt_large_step(char* plaintext, char* ciphertext);
int aes_crypt_large_end(char* ciphertext);


#endif // __AES_EVP_INC__
