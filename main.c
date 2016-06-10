#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"

int main(int argc, char** argv)
{
    char plaintext[256] = "pompom";
    char ciphertext[256] = {0};

    if(0 != aes_evp_crypt(
        plaintext,
        ciphertext,
        "teste",
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
        "teste",
        AES_EVP_DECRYPT))
    {
        printf("error\n");
    }
    else
    {
        printf("Decrypted text is: %s\n", plaintext);
    }

    return 0;
}
