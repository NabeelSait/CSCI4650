#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <iostream>
#include <fstream>

using namespace std;

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char *argv[])
{
   if (argc != 5)
   {
      cout << "Invalid amount of arguments \n";
      abort();
   }

   //Loading the encyrpted session key and determining length
   ifstream input(argv[3]);
   string encrypted_k( (istreambuf_iterator<char>(input) ), (istreambuf_iterator<char>()    ) );
   unsigned char* ek = (unsigned char*)encrypted_k;
   int eklen = encyrpted_k.length();

   //Loading the public key used for decryption
   input = argv[4];
   string public_k( (istreambuf_iterator<char>(input) ), (istreambuf_iterator<char>()    ) );
   unsigned char* publicKey = (unsigned char*)public_k;

   unsigned char *iv = (unsigned char *) malloc(EVP_MAX_IV_LENGTH);
   // initialize decrypt context
   EVP_CIPHER_CTX *rsaDecryptCtx = (EVP_CIPHER_CTX *) malloc(sizeof(EVP_CIPHER_CTX));
   EVP_CIPHER_CTX_init(rsaDecryptCtx);

   EVP_OpenInit(rsaDecryptCtx, EVP_des_cbc(), ek, ekLen, iv, publicKey);
}
