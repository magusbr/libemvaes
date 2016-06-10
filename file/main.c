#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "base64.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/**
 * Encrypt or decrypt, depending on flag 'should_encrypt'
 */
void en_de_crypt(int should_encrypt, FILE *ifp, FILE *ofp, unsigned char *ckey, unsigned char *ivec) {

    const unsigned BUFSIZE=4096;
    unsigned char *read_buf = malloc(BUFSIZE);
    unsigned char *cipher_buf;
    unsigned blocksize;
    int out_len;
    EVP_CIPHER_CTX ctx;
    char* b64buf = NULL;

    EVP_CipherInit(&ctx, EVP_aes_256_cbc(), ckey, ivec, should_encrypt);
    blocksize = EVP_CIPHER_CTX_block_size(&ctx);
    cipher_buf = malloc(BUFSIZE + blocksize);

    while (1) {

        // Read in data in blocks until EOF. Update the ciphering with each read.

        int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
        if (should_encrypt == FALSE)
        {
            read_buf[numRead] = 0;
            printf("decrypt b64 %d %s\n", numRead, read_buf);
            Base64Decode((char*)read_buf, (unsigned char**)&b64buf, &numRead);
            memcpy(read_buf, b64buf, numRead);
            read_buf[numRead] = 0;
        }


        EVP_CipherUpdate(&ctx, cipher_buf, &out_len, read_buf, numRead);
        //fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
        if (numRead < BUFSIZE) { // EOF
            break;
        }
    }


    // Now cipher the final block and write it out.

    EVP_CipherFinal(&ctx, cipher_buf, &out_len);
    if (should_encrypt == TRUE)
    {
        Base64Encode((unsigned char*)cipher_buf, out_len, &b64buf);
    }
    else
    {
        printf("decrypted %s\n", cipher_buf);
        memcpy(b64buf, cipher_buf, strlen((char*)cipher_buf));
        b64buf[strlen((char*)cipher_buf)] = 0;
    }
    fwrite(b64buf, sizeof(unsigned char), strlen(b64buf), ofp);
    free(b64buf);

    // Free memory

    free(cipher_buf);
    free(read_buf);
}

int main(int argc, char *argv[]) {

    unsigned char ckey[] = "pass";
    unsigned char* ivec = NULL;// ivec[] = "dontusethisinput";
    FILE *fIN, *fOUT;

    /*if (argc != 2) {
        printf("Usage: <executable> /path/to/file/exe");
        return -1;
    }*/

    // First encrypt the file

    fIN = fopen("plain.txt", "rb"); //File to be encrypted; plain text
    fOUT = fopen("cyphertext.txt", "wb"); //File to be written; cipher text

    en_de_crypt(TRUE, fIN, fOUT, ckey, ivec);

    fclose(fIN);
    fclose(fOUT);

    //Decrypt file now

    fIN = fopen("cyphertext.txt", "rb"); //File to be read; cipher text
    fOUT = fopen("decrypted.txt", "wb"); //File to be written; cipher text

    en_de_crypt(FALSE, fIN, fOUT, ckey, ivec);

    fclose(fIN);
    fclose(fOUT);

    return 0;
}
