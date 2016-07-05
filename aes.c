#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>
#include "aes.h"
#include "base64.h"
#include "urandom.h"

#define SALT_HEADER_SIZE    16

void aes_evp_handle_errors(void)
{
    #ifdef __DEBUG__
        ERR_print_errors_fp(stderr);
    #endif
    abort();
}

int aes_evp_cipher_add_salt(unsigned char* cipher, int* size, char* salt)
{
    const char* salt_header_prefix = "Salted__";
    char* salt_header[SALT_HEADER_SIZE+1];
    sprintf((char*)salt_header,
        "%s%.*s",
        salt_header_prefix,
        (int)(SALT_HEADER_SIZE-strlen(salt_header_prefix)), // whats left after prefix
        (char*)salt);

    if (*size == 0)
    {
        memcpy(cipher, salt_header, SALT_HEADER_SIZE);
    }
    else
    {
        unsigned char tmp_cipher[*size];
        memcpy(tmp_cipher, cipher, *size);
        memcpy(cipher, salt_header, SALT_HEADER_SIZE);
        memcpy(cipher+SALT_HEADER_SIZE, tmp_cipher, *size);
    }

    *size += SALT_HEADER_SIZE;

    return 0;
}

int pass_to_key(unsigned char* key, unsigned char* iv, unsigned char* salt, unsigned char* password)
{
    const EVP_CIPHER *cipher;
    const EVP_MD *dgst = NULL;

    // already done at main
    //OpenSSL_add_all_algorithms();

    cipher = EVP_get_cipherbyname("aes-256-cbc");
    if(!cipher)
    {
        #ifdef __DEBUG__
            fprintf(stderr, "no such cipher\n");
        #endif
        return -1;
    }

    dgst=EVP_get_digestbyname("md5");
    if(!dgst)
    {
        #ifdef __DEBUG__
            fprintf(stderr, "no such digest\n");
        #endif
        return -1;
    }

    if(!EVP_BytesToKey(cipher, dgst, salt,
        (unsigned char *) password,
        strlen((char*)password), 1, key, iv))
    {
        #ifdef __DEBUG__
            fprintf(stderr, "EVP_BytesToKey failed\n");
        #endif
        return -1;
    }

    #ifdef __DEBUG__
        int i;
        printf("Key: ");
        for(i=0; i<cipher->key_len; ++i) { printf("%02x", key[i]); } printf("\n");
        printf("IV: ");
        for(i=0; i<cipher->iv_len; ++i) { printf("%02x", iv[i]); } printf("\n");
    #endif

    return 0;
}

int aes_evp_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) aes_evp_handle_errors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        aes_evp_handle_errors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        aes_evp_handle_errors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) aes_evp_handle_errors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_evp_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) aes_evp_handle_errors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        aes_evp_handle_errors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        aes_evp_handle_errors();
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        aes_evp_handle_errors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void aes_evp_cleanup()
{
    /* Clean up */
    EVP_cleanup();
    #ifdef __DEBUG__
        ERR_free_strings();
    #endif
}

int aes_evp_crypt(char* plaintext, char* ciphertext, const char* password, int enc_dec)
{
    // Variables to store salt random value
    unsigned long ul_salt = 0;
    char salt[9] = {0};

    // Set up the key and iv.
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

    int decryptedtext_len, ciphertext_len;

    if (((plaintext[0] == '\0') && (enc_dec == AES_EVP_ENCRYPT))
        || ((ciphertext[0] == '\0') && (enc_dec == AES_EVP_DECRYPT)))
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

    if (enc_dec == AES_EVP_ENCRYPT)
    {
        // generate key and iv using salt
        // need to use snprintf, because X. limits only for %s
        snprintf(salt, 9, "%8.8lu", ul_salt);
        pass_to_key(
            key,
            iv,
            (unsigned char*)salt,
            (unsigned char*)password);

        // Encrypt the plaintext
        ciphertext_len = aes_evp_encrypt(
            (unsigned char*)plaintext,
            strlen ((char *)plaintext),
            key,
            iv,
            (unsigned char*)ciphertext);

        if (0 != aes_evp_cipher_add_salt(
            (unsigned char*)ciphertext,
            &ciphertext_len,
            salt))
        {
            aes_evp_cleanup();
            return -1;
        }

        #ifdef __DEBUG__
            // Dump hex
            printf("Salted ciphertext hex is:\n");
            BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
        #endif

        Base64Encode((unsigned char*)ciphertext, ciphertext_len);
        ciphertext_len = strlen(ciphertext);

        #ifdef __DEBUG__
            // base64
            printf("Ciphertext is: %s\n", ciphertext);
        #endif
    }
    else
    {
        ciphertext_len = strlen(ciphertext);
        Base64Decode((char*)ciphertext, &ciphertext_len);

        // generate key and iv using obtained salt
        memcpy(salt, &ciphertext[8], 8);
        salt[8] = 0;
        pass_to_key(
            key,
            iv,
            (unsigned char*)salt,
            (unsigned char*)password);

        #ifdef __DEBUG__
            printf("Salted ciphertext hex is:\n");
            BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
        #endif
        ciphertext_len -= SALT_HEADER_SIZE;
        /* Decrypt the ciphertext */
        decryptedtext_len = aes_evp_decrypt(
            (unsigned char*)ciphertext+SALT_HEADER_SIZE,
            ciphertext_len,
            key,
            iv,
            (unsigned char*)plaintext);

        // Add a NULL terminator. We are expecting printable text
        plaintext[decryptedtext_len] = '\0';

        #ifdef __DEBUG__
            // Show the decrypted text
            printf("Decrypted text is:\n");
            printf("%s\n", plaintext);
        #endif
    }

    aes_evp_cleanup();
    return 0;
}

