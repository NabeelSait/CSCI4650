#include <iostream>
#include <fstream>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>

using namespace std;


int main(int argc, char *argv[])
{
   if (argc != 5)
   {
      cout << "Invalid amount of arguments \n";
      abort();
   }

   //Loading the encyrpted session key and determining length
   ifstream encrypted_k_input(argv[3]);
   string encrypted_k( (istreambuf_iterator<char>(encrypted_k_input) ), (istreambuf_iterator<char>()    ) );
   size_t eklen = encrypted_k.length();
   const unsigned char* ek = reinterpret_cast<const unsigned char *> (encrypted_k.c_str());

   //Loading the public key used for decryption
   ifstream public_k_input(argv[3]);
   string public_k( (istreambuf_iterator<char>(public_k_input) ), (istreambuf_iterator<char>()    ) );
   const char* publicKey = public_k.c_str();
   EVP_PKEY* key;
   size_t keylen;
   key = EVP_PKEY_new_raw_public_key(NULL, NULL, publicKey, keylen);

   // initialize decrypt context
   EVP_PKEY_CTX* ctx;

   ctx = EVP_PKEY_CTX_new(key, NULL);

   int s = EVP_PKEY_decrypt_init(ctx);
   unsigned char *out = NULL;
   size_t* outlen;
   int d = EVP_PKEY_decrypt(ctx, out, outlen, ek, eklen);
}
