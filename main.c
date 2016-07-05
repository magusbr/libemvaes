#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"

int rsa_main();

int main(int argc, char** argv)
{
    char plaintext[256] = "pompom";
    char ciphertext[256] = {0};
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

    strcpy(plaintext, "pompom");
    memset(ciphertext, 0, sizeof(ciphertext));
    aes_crypt_large_init(plaintext, ciphertext, key);
    printf("1 %s\n", ciphertext);

    strcpy(plaintext, "mopmop1");
    memset(ciphertext, 0, sizeof(ciphertext));
    aes_crypt_large_step(plaintext, ciphertext);
    printf("2 %s\n", ciphertext);

    strcpy(plaintext, "mopmop2");
    memset(ciphertext, 0, sizeof(ciphertext));
    aes_crypt_large_step(plaintext, ciphertext);
    printf("3 %s\n", ciphertext);

    strcpy(plaintext, "e tal");
    memset(ciphertext, 0, sizeof(ciphertext));
    aes_crypt_large_step(plaintext, ciphertext);
    printf("4 %s\n", ciphertext);

    memset(ciphertext, 0, sizeof(ciphertext));
    aes_crypt_large_end(ciphertext);
    printf("5 %s\n", ciphertext);

    return 0;
}
