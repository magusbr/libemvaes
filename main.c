#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"

int rsa_main();

int main(int argc, char** argv)
{
    char plaintext[256] = "pompom";
    char ciphertext[256] = {0};
    char ciphertext1[256] = {0};
    char ciphertext2[256] = {0};
    char ciphertext3[256] = {0};
    char ciphertext4[256] = {0};
    char ciphertext5[256] = {0};
    char key[256] = "teste";

    printf("AES\n");

    if(0 != aes_evp_crypt(
        plaintext,
        ciphertext,
        key,
        AES_EVP_ENCRYPT))
    {
        printf("error\n");
    }
    else
    {
        printf("Ciphertext is: %s\n", ciphertext);
    }

    memset(plaintext, 0, sizeof(plaintext));
    
    if(0 != aes_evp_crypt(
        plaintext,
        ciphertext,
        key,
        AES_EVP_DECRYPT))
    {
        printf("error\n");
    }
    else
    {
        printf("Decrypted text is: %s\n", plaintext);
    }

    printf("RSA\n");

    rsa_main();


    printf("AES LARGE\n");

    strcpy(plaintext, "pompompompompompom");
    aes_crypt_large_init(plaintext, ciphertext1, key);
    printf("1 %s\n", ciphertext1);

    strcpy(plaintext, "mopmop1");
    aes_crypt_large_step(plaintext, ciphertext2);
    printf("2 %s\n", ciphertext3);

    strcpy(plaintext, "mopmop2");
    aes_crypt_large_step(plaintext, ciphertext3);
    printf("3 %s\n", ciphertext3);

    strcpy(plaintext, "e tal");
    aes_crypt_large_step(plaintext, ciphertext4);
    printf("4 %s\n", ciphertext4);

    aes_crypt_large_end(ciphertext5);
    printf("5 %s\n", ciphertext5);


    printf("AES LARGE DEC\n");

    int len;

    // need to make sure first cirphertext contain salt (24) + 1 character
    memset(plaintext, 0, sizeof(plaintext));
    len = aes_decrypt_large_init(plaintext, ciphertext1, key);
    printf("1 %.*s\n", len, plaintext);

    memset(plaintext, 0, sizeof(plaintext));
    len = aes_decrypt_large_step(plaintext, ciphertext2);
    printf("2 %.*s\n", len, plaintext);

    memset(plaintext, 0, sizeof(plaintext));
    len = aes_decrypt_large_step(plaintext, ciphertext3);
    printf("3 %.*s\n", len, plaintext);

    memset(plaintext, 0, sizeof(plaintext));
    len = aes_decrypt_large_step(plaintext, ciphertext4);
    printf("4 %.*s\n", len, plaintext);

    memset(plaintext, 0, sizeof(plaintext));
    len = aes_decrypt_large_step(plaintext, ciphertext5);
    printf("5 %.*s\n", len, plaintext);

    memset(plaintext, 0, sizeof(plaintext));
    len = aes_decrypt_large_end(plaintext);
    printf("6 %.*s\n", len, plaintext);
    return 0;
}
