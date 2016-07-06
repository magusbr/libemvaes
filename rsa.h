#ifndef __RSA_INC__
#define __RSA_INC__

typedef enum rsa_type
{
    RSA_ENCRYPT = 0,
    RSA_DECRYPT
} rsa_type;

int rsa_main();
int rsa_crypt(char* plaintext, char* ciphertext, int enc_dec);


#endif // __RSA_INC__
