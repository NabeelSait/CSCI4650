#include <iostream>
#include <utility>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

#include "CryptoFunctions.h"

using namespace std;

int main(int argc, char *argv[])
{
   size_t size = getFileByteSize("plaintext.txt");
   unsigned char * plaintext = (unsigned char *) malloc(size);
   size_t p_len;
   FiletoChar("plaintext.txt", size, plaintext, &p_len);
   EnvelopeOpen("encrypted_session.key", "TPpubkey.pem", plaintext, p_len);
   // EncryptPlaintext(out, outlen, plaintext, *p_len);

   SignPlaintext(plaintext, p_len, "TPprivkey");
   free(plaintext);
}
