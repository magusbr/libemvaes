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

    return 0;
}
