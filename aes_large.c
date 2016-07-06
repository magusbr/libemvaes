#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>
#include "aes.h"
#include "base64.h"
#include "urandom.h"

#define SALT_HEADER_SIZE    16

static unsigned char key_large[EVP_MAX_KEY_LENGTH] = {0};
static unsigned char iv_large[EVP_MAX_IV_LENGTH] = {0};
static EVP_CIPHER_CTX *ctx_large = 0;
static unsigned char leftover[4] = {0};
static int leftover_len = 0;

int aes_crypt_large_error()
{
    #ifdef __DEBUG__
        ERR_print_errors_fp(stderr);
    #endif
    //abort();

    if (ctx_large != NULL)
        EVP_CIPHER_CTX_free(ctx_large);

    ctx_large = NULL;

    return -1;
}

int aes_crypt_large_init(char* plaintext, char* ciphertext, const char* password)
{
    // Variables to store salt random value
    unsigned long ul_salt = 0;
    char salt[9] = {0};
    int len;
    leftover_len = 0;

    int ciphertext_len;
    int plaintext_len = strlen(plaintext);

    if (plaintext[0] == '\0')
        return -1;

    ul_salt = urandom();
    if (ul_salt == -1)
    {
        #ifdef __DEBUG__
            printf("error generating salt\n");
        #endif
        return -1;
    }

    /* Initialise the library */
    #ifdef __DEBUG__
        ERR_load_crypto_strings();
    #endif
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    // generate key and iv using salt
    // need to use snprintf, because X. limits only for %s
    snprintf(salt, 9, "%8.8lu", ul_salt) ;

    pass_to_key(
        key_large,
        iv_large,
        (unsigned char*)salt,
        (unsigned char*)password);

    /* Create and initialise the context */
    if(!(ctx_large = EVP_CIPHER_CTX_new()))
        return aes_crypt_large_error();

    if(1 != EVP_EncryptInit_ex(
        ctx_large,
        EVP_aes_256_cbc(),
        NULL,
        key_large,
        iv_large)
    )
        return aes_crypt_large_error();

    if(1 != EVP_EncryptUpdate(
        ctx_large,
        (unsigned char*)ciphertext,
        &len,
        (unsigned char*)plaintext,
        plaintext_len)
    )
        return aes_crypt_large_error();

    ciphertext_len = len;

    if (0 != aes_evp_cipher_add_salt(
        (unsigned char*)ciphertext,
        &ciphertext_len,
        salt))
    {
        return aes_crypt_large_error();
    }

    #ifdef __DEBUG__
        // Dump hex
        printf("Salted ciphertext hex is:\n");
        BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    #endif

    if (ciphertext_len)
    {
        // adjust to base64 size
        leftover_len = ciphertext_len % 3;
        if (leftover_len > 0)
        {
            memcpy(leftover, ciphertext + ciphertext_len - leftover_len, leftover_len);
            ciphertext_len -= leftover_len;
        }
 
        Base64Encode((unsigned char*)ciphertext, ciphertext_len);
        ciphertext_len = strlen(ciphertext);
    }

    return ciphertext_len;
}

int aes_crypt_large_step(char* plaintext, char* ciphertext)
{
    int len = 0;
    int ciphertext_len = 0;
    int plaintext_len = strlen(plaintext);

    if(1 != EVP_EncryptUpdate(
        ctx_large,
        (unsigned char*)ciphertext+leftover_len,
        &len,
        (unsigned char*)plaintext,
        plaintext_len)
    )
        return aes_crypt_large_error();

    ciphertext_len = len;

    #ifdef __DEBUG__
        // Dump hex
        printf("Salted ciphertext hex is:\n");
        BIO_dump_fp (stdout, (const char *)ciphertext+leftover_len, ciphertext_len);
    #endif

    if (ciphertext_len)
    {
        if (leftover_len > 0)
        {
            memcpy(ciphertext, leftover, leftover_len);
            ciphertext_len += leftover_len;
        }

        // adjust to base64 size
        leftover_len = ciphertext_len % 3;
        if (leftover_len > 0)
        {
            memcpy(leftover, ciphertext + ciphertext_len - leftover_len, leftover_len);
            ciphertext_len -= leftover_len;
        }

        Base64Encode((unsigned char*)ciphertext, ciphertext_len);
        ciphertext_len = strlen(ciphertext);
    }

    return ciphertext_len;
}

int aes_crypt_large_end(char* ciphertext)
{
    int len = 0;
    int ciphertext_len = 0;

    if(1 != EVP_EncryptFinal_ex(
        ctx_large,
        (unsigned char*)(ciphertext + leftover_len),
        &len)
    )
        return aes_crypt_large_error();

    ciphertext_len += len;

    if (leftover_len > 0)
    {
        memcpy(ciphertext, leftover, leftover_len);
        ciphertext_len += leftover_len;
    }

    // if something still need to be encoded
    if (ciphertext_len > 0)
    {
        Base64Encode((unsigned char*)ciphertext, ciphertext_len);
        ciphertext_len = strlen(ciphertext);
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx_large);

    ctx_large = NULL;

    return ciphertext_len;
}



















// need to make sure first cirphertext contain salt (24) + 1 character
int aes_decrypt_large_init(char* plaintext, char* ciphertext, const char* password)
{
    // Variables to store salt random value
    char salt[9] = {0};

    int ciphertext_len = strlen(ciphertext);
    int plaintext_len;

    if (ciphertext_len <= 24)
        return -1;
    
    /* Initialise the library */
    #ifdef __DEBUG__
        ERR_load_crypto_strings();
    #endif
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    
    Base64Decode((char*)ciphertext, &ciphertext_len);

    // generate key and iv using obtained salt
    memcpy(salt, &ciphertext[8], 8);
    salt[8] = 0;
    pass_to_key(
        key_large,
        iv_large,
        (unsigned char*)salt,
        (unsigned char*)password);

    #ifdef __DEBUG__
        printf("Salted ciphertext hex is:\n");
        BIO_dump_fp (stdout, (const char *)ciphertext+SALT_HEADER_SIZE, ciphertext_len);
    #endif
    ciphertext_len -= SALT_HEADER_SIZE;

    /* Create and initialise the context */
    if(!(ctx_large = EVP_CIPHER_CTX_new()))
        return aes_crypt_large_error();
        
    if(1 != EVP_DecryptInit_ex(
        ctx_large,
        EVP_aes_256_cbc(),
        NULL, key_large, iv_large)
    )
        return aes_crypt_large_error();

    if(1 != EVP_DecryptUpdate(
        ctx_large,
        (unsigned char*)plaintext,
        &plaintext_len,
        (unsigned char*)ciphertext+SALT_HEADER_SIZE,
        ciphertext_len)
    )
        return aes_crypt_large_error();

    return plaintext_len;
}


int aes_decrypt_large_step(char* plaintext, char* ciphertext)
{
    int plaintext_len = 0;
    int ciphertext_len = strlen(ciphertext);

    if (ciphertext_len == 0)
        return -1;
    
    Base64Decode((char*)ciphertext, &ciphertext_len);

    #ifdef __DEBUG__
        printf("Ciphertext hex is:\n");
        BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    #endif
    
    if(1 != EVP_DecryptUpdate(
        ctx_large,
        (unsigned char*)plaintext,
        &plaintext_len,
        (unsigned char*)ciphertext,
        ciphertext_len)
    )
        return aes_crypt_large_error();
    
    return plaintext_len;
}



int aes_decrypt_large_end(char* plaintext)
{
    int plaintext_len = 0;

    if(1 != EVP_DecryptFinal_ex(
        ctx_large,
        (unsigned char*)plaintext,
        &plaintext_len)
    )
        aes_crypt_large_error();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx_large);

    ctx_large = NULL;

    return plaintext_len;
}
