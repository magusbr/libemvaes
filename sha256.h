#ifndef __SHA_EVP_INC__
#define __SHA_EVP_INC__

void sha256(char *string, char outputBuffer[65]);
int sha256_file(char *path, char outputBuffer[65]);

#endif // __SHA_EVP_INC__
