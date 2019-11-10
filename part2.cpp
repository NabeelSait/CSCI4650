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

using namespace std;

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

pair<unsigned char*, size_t> FiletoChar(const char* filename);

void ChartoFile(unsigned char* out, size_t size, const char* filename);

size_t getFileByteSize(const char* filename);

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
   if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ek, eklen) <= 0)
   {
      fprintf(stderr, "Cannot determine buffer");
   }

   out = (unsigned char*) malloc(outlen);

   EVP_PKEY_decrypt(ctx, out, &outlen, ek, eklen);


   ChartoFile(out, outlen, "test_key.key");


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

   size_t c_len = strlen ((char*)ciphertext);
   ChartoFile(ciphertext, c_len, "ciphertext.txt");
}


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        fprintf(stderr, "Ctx Faliure");

    cout << "CTX succeeded" << "\n";

    if(1 != EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv))
        fprintf(stderr, "Intitiation Faliure");

    cout << "Initiation Succeeded" << "\n";

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        fprintf(stderr, "Update Faliure");

    cout << "Update Succeeded \n";

    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        fprintf(stderr, "Final Update");

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

pair<unsigned char*, size_t> FiletoChar(const char* filename)
{
   //Loading the encyrpted session key
   FILE * file = fopen(filename, "r+");
   if (file == NULL)
   {
      fprintf(stderr, "File not read");
   }
   fseek(file, 0, SEEK_END);
   size_t size = ftell(file);
   fclose(file);

   // Reading data to array of unsigned chars
   file = fopen(filename, "r+");
   unsigned char * c = (unsigned char *) malloc(size);
   size_t clen = fread(c, sizeof(unsigned char), size, file);
   fclose(file);

   pair <unsigned char*, size_t>  p (c, clen);

   return p;
}

void ChartoFile(unsigned char* out, size_t size, const char* filename)
{
   FILE* file = fopen(filename, "w+");
   int bytes_written = fwrite(out, sizeof(unsigned char), size, file);
   fclose(file);
}

size_t getFileByteSize(const char* filename)
{
   //Loading the encyrpted session key
   FILE * file = fopen(filename, "r+");
   if (file == NULL)
   {
      fprintf(stderr, "File not read");
   }
   fseek(file, 0, SEEK_END);
   size_t size = ftell(file);
   fclose(file);

   return size;
}

// void SignMessage(EVP_PKEY* key, unsigned char* msg)
// {
//    EVP_MD_CTX *mdctx = NULL;
//    int ret = 0;
//
//    *sig = NULL;
//
//    /* Create the Message Digest Context */
//     if(!(mdctx = EVP_MD_CTX_create())) goto err;
//
//    /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
//     if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key)) goto err;
//
//     /* Call update with the message */
//     if(1 != EVP_DigestSignUpdate(mdctx, msg, strlen(msg))) goto err;
//
//     /* Finalise the DigestSign operation */
//     /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
//      * signature. Length is returned in slen */
//     if(1 != EVP_DigestSignFinal(mdctx, NULL, slen)) goto err;
//     /* Allocate memory for the signature based on size in slen */
//     if(!(*sig = OPENSSL_malloc(sizeof(unsigned char) * (*slen)))) goto err;
//     /* Obtain the signature */
//     if(1 != EVP_DigestSignFinal(mdctx, *sig, slen)) goto err;
//
//     /* Success */
//     ret = 1;
//
//     err:
//     if(ret != 1)
//     {
//       fprintf(stderr, "Errors Hapenned. Consider crying");
//     }
//
//     /* Clean up */
//     if(*sig && !ret) OPENSSL_free(*sig);
//     if(mdctx) EVP_MD_CTX_destroy(mdctx);
// }
