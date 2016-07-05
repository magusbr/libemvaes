#ifndef __BASE64_INC__
#define __BASE64_INC__

int calcEncodeLength(int length);
int Base64Encode(unsigned char* inout, int length);
int Base64Decode(char* inout, int* length);


#endif
