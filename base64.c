#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <assert.h>
#include <math.h>

int Base64Encode(char* inout, int length) {
    //Encodes a binary safe base 64 string
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    //Ignore newlines - write everything in one line
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, inout, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    //*b64text = (char*)malloc(bufferPtr->length+1);
    memcpy(inout, bufferPtr->data, bufferPtr->length);
    inout[bufferPtr->length] = 0;

    // avoid deallocation of buffer
    //BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    // used together with BIO_set_close
    //*b64text=(*bufferPtr).data;

    return (0); //success
}

int calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
    int len = strlen(b64input),
        padding = 0;

    //last two chars are =
    if (b64input[len-1] == '=' && b64input[len-2] == '=')
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;

    return (len*3)/4 - padding;
}

int calcEncodeLength(int length)
{
    // each 3 (or less) bytes will become 4 bytes
    return 4*(int)ceil((float)length/(float)3);
}

int Base64Decode(char* inout, int* length) {
    //Decodes a base64 encoded string
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(inout);
    //*buffer = (unsigned char*)malloc(decodeLen + 1);
    char buffer[decodeLen];

    bio = BIO_new_mem_buf(inout, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    //Do not use newlines to flush buffer
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *length = BIO_read(bio, buffer, strlen(inout));
    BIO_free_all(bio);

    //length should equal decodeLen, else something went horribly wrong
    if (*length != decodeLen)
        return -1;

    memcpy(inout, buffer, *length);

    return (0); //success
}
