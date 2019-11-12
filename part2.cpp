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
   pair <unsigned char *, size_t> p = FiletoChar("encrypted_session.key");

   unsigned char* ek = p.first;
   size_t eklen = p.second;

   EVP_PKEY* pPubKey  = NULL;
   FILE*     pFile    = NULL;

   pPubKey = NULL;
   if((pFile = fopen("TPpubkey.pem","rt")) && (pPubKey = PEM_read_PUBKEY(pFile,NULL,NULL,NULL)))
   {
      fprintf(stderr,"Public key read.\n");
   }
   else
   {
      fprintf(stderr,"Cannot read \"pubkey.pem\".\n");
   }

   unsigned char * out;
   size_t outlen;
   EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pPubKey, NULL);

   EVP_PKEY_decrypt_init(ctx);

   cout << "Initialization Success \n";

   if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ek, eklen) <= 0)
   {
      fprintf(stderr, "Cannot determine buffer");
   }

   out = (unsigned char*) malloc(outlen);

   EVP_PKEY_decrypt(ctx, out, &outlen, ek, eklen);
   ChartoFile(out, outlen, "test_key.key");

   cout << "Decryption Success \n";

   unsigned char iv[64];

   unsigned char ciphertext[outlen + 128];

   if(!(RAND_bytes(iv, sizeof(iv))))
   {
      fprintf(stderr, "IV generation error");
   }

   p = FiletoChar("plaintext.txt");
   unsigned char * plaintext = p.first;

   size_t p_len = p.second;

   encrypt(plaintext, p_len, out, NULL, ciphertext);

   cout << "Encryption Success \n";

   size_t c_len = strlen ((char*)ciphertext);
   ChartoFile(ciphertext, c_len, "ciphertext.txt");

   EVP_PKEY* pPrivKey;
   if((pFile = fopen("privkey.pem","rt")) && (pPrivKey = PEM_read_PrivateKey(pFile,NULL,NULL,NULL)))
   {
      fprintf(stderr,"Private key read.\n");
   }
   else
   {
      fprintf(stderr,"Cannot read \"privkey.pem\".\n");
   }

   p = SignMessage(pPrivKey, plaintext, p_len);
   unsigned char* sig = p.first;
   size_t slen = p.second;

   ChartoFile(sig, slen, "signature.txt");
}
