#include <iostream>
#include <fstream>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;


int main(int argc, char *argv[])
{
   // if (argc != 5)
   // {
   //    cout << "Invalid amount of arguments \n";
   //    abort();
   // }

   //Loading the encyrpted session key and determining length
   ifstream encrypted_k_input(argv[3]);
   string encrypted_k( (istreambuf_iterator<char>(encrypted_k_input) ), (istreambuf_iterator<char>()    ) );
   size_t eklen = encrypted_k.length();
   const unsigned char* ek = reinterpret_cast<const unsigned char *> (encrypted_k.c_str());

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

   EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pPubKey, NULL);

   EVP_PKEY_decrypt_init(ctx);
   unsigned char * out = NULL;
   size_t* outlen = NULL;
   if (!(1 == EVP_PKEY_decrypt(ctx, NULL, NULL, ek, eklen)))
   {
      fprintf(stderr, "Decryption Failure");
   }
   else
   {
      fprintf(stderr, "Decryption succeeded");
   }
}
