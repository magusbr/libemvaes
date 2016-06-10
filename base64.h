#ifndef __BASE64_INC__
#define __BASE64_INC__

int calcEncodeLength(int length);
int Base64Encode(const unsigned char* buffer, int length, char* b64text);
int Base64Decode(char* b64message, unsigned char* buffer, int* length);


#endif
