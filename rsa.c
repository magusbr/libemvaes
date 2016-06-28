#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

#include "base64.h"
#include "rsa.h"

// from
// http://hayageek.com/rsa-encryption-decryption-openssl-c/

int padding = RSA_PKCS1_PADDING;
#define PVKF "/home/magusbr/data/privatekey.pem"
#define PBKF "/home/magusbr/data/publickey.pem"

void rsa_cleanup()
{
    /* Clean up */
    EVP_cleanup();
    #ifdef __DEBUG__
        ERR_free_strings();
    #endif
}

void rsa_handle_errors(void)
{
    #ifdef __DEBUG__
        ERR_print_errors_fp(stderr);
    #endif
    abort();
}

RSA* createRSAWithFilename(char * filename,int public)
{
    FILE * fp = fopen(filename,"rb");

    if(fp == NULL)
    {
        #ifdef __DEBUG__
            fprintf(stderr, "Unable to open file %s \n",filename);
        #endif
        return NULL;    
    }
    RSA *rsa= RSA_new() ;

    if(public)
    {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
    }

    fclose(fp);

    return rsa;
}


RSA* createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        #ifdef __DEBUG__
            printf(stderr, "Failed to create key BIO\n");
        #endif
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        #ifdef __DEBUG__
            fprintf(stderr, "Failed to create RSA\n");
        #endif
    }

    return rsa;
}

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    //RSA * rsa = createRSA(key,1);
    RSA* rsa = createRSAWithFilename(PBKF, 1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    //RSA * rsa = createRSA(key,0);
    RSA* rsa = createRSAWithFilename(PVKF, 0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}


int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    //RSA * rsa = createRSA(key,0);
    RSA* rsa = createRSAWithFilename(PVKF, 0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    //RSA * rsa = createRSA(key,1);
    RSA* rsa = createRSAWithFilename(PBKF, 1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

void printLastError(char *msg)
{
    #ifdef __DEBUG__
        char * err = malloc(130);;
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "%s ERROR: %s\n",msg, err);
        free(err);
    #endif
}

int rsa_main_demo()
{
    char plainText[2048/8] = "Hello this is Ravi"; //key length : 2048

    char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";
 
    char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n";

   
    unsigned char encrypted[4098]={};
    unsigned char decrypted[4098]={};

    int encrypted_length= public_encrypt((unsigned char*)plainText,strlen(plainText),(unsigned char*)publicKey,encrypted);
    if(encrypted_length == -1)
    {
        printLastError("Public Encrypt failed ");
        exit(0);
    }

    #ifdef __DEBUG__
        printf("Encrypted length =%d\n",encrypted_length);
    #endif

    int decrypted_length = private_decrypt((unsigned char*)encrypted,encrypted_length,(unsigned char*)privateKey, decrypted);
    if(decrypted_length == -1)
    {
        printLastError("Private Decrypt failed ");
        exit(0);
    }
    #ifdef __DEBUG__
        printf("Decrypted Text =%s\n",decrypted);
        printf("Decrypted Length =%d\n",decrypted_length);
    #endif

    encrypted_length= private_encrypt((unsigned char*)plainText,strlen(plainText),(unsigned char*)privateKey,encrypted);
    if(encrypted_length == -1)
    {
        printLastError("Private Encrypt failed");
        exit(0);
    }
    #ifdef __DEBUG__
        printf("Encrypted length =%d\n",encrypted_length);
    #endif

    decrypted_length = public_decrypt((unsigned char*)encrypted,encrypted_length,(unsigned char*)publicKey, decrypted);
    if(decrypted_length == -1)
    {
        printLastError("Public Decrypt failed");
        exit(0);
    }
    #ifdef __DEBUG__
        printf("Decrypted Text =%s\n",decrypted);
        printf("Decrypted Length =%d\n",decrypted_length);
    #endif

    return 0;
}


int rsa_main()
{
    char plaintext[2048] = "pompom";
    char ciphertext[2048] = {0};

    if(0 != rsa_crypt(
        plaintext,
        ciphertext,
        RSA_ENCRYPT))
    {
        printf("error\n");
    }
    else
    {                                                                                                                   printf("Ciphertext is: %s\n", ciphertext);
    }

    memset(plaintext, 0, sizeof(plaintext));

    if(0 != rsa_crypt(
        plaintext,
        ciphertext,
        RSA_DECRYPT))
    {
        printf("error\n");
    }
    else
    {
        printf("Decrypted text is: %s\n", plaintext);
    }

    return 0;
}


int rsa_crypt(char* plaintext, char* ciphertext, int enc_dec)
{
    char b64buf[2048] = {0};
    int decryptedtext_len, ciphertext_len;

    /* Initialise the library */
    #ifdef __DEBUG__
        ERR_load_crypto_strings();
    #endif

    if (enc_dec == RSA_ENCRYPT)
    {
        ciphertext_len = public_encrypt(
            (unsigned char*)plaintext,
            strlen(plaintext),
            NULL,
            (unsigned char*)ciphertext);

        if(ciphertext_len == -1)
        {
            rsa_handle_errors();
            rsa_cleanup();
            return -1;
        }

        #ifdef __DEBUG__
            // Dump hex
            printf("ciphertext hex is:\n");
            BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
        #endif

        Base64Encode((unsigned char*)ciphertext, ciphertext_len, b64buf);
        strcpy((char*)ciphertext, b64buf);
        ciphertext_len = strlen(ciphertext);
                                                                                                                        #ifdef __DEBUG__
            // base64
            printf("Ciphertext is: %s\n", ciphertext);
        #endif  
    }
    else
    {
        ciphertext_len = strlen(ciphertext);
        Base64Decode((char*)ciphertext, (unsigned char*)b64buf, &ciphertext_len);

        #ifdef __DEBUG__
            printf("Ciphertext hex is:\n");
            BIO_dump_fp (stdout, (const char *)b64buf, ciphertext_len);
        #endif

        memcpy(ciphertext, b64buf, ciphertext_len);

        decryptedtext_len = private_decrypt(
            (unsigned char*)ciphertext,
            ciphertext_len,
            NULL,
            (unsigned char*)plaintext);

        if (decryptedtext_len == -1)
        {
            printLastError("Private Decrypt failed ");
            exit(0);
        }

        // Add a NULL terminator. We are expecting printable text
        plaintext[decryptedtext_len] = '\0';

        #ifdef __DEBUG__
            // Show the decrypted text
            printf("Decrypted text is:\n");
            printf("%s\n", plaintext);
        #endif
    }

    rsa_cleanup();
    return 0;
}
