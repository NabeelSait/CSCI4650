#include <utility>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>



using namespace std;

#ifndef CRYPTO_FUNCTIONS_H
#define CRYPTO_FUNCTIONS_H

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
        fprintf(stderr, "Final Update Failed \n");

    fprintf(stderr, "Final Update Succeeded \n");

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
   char** out;
   Base64Encode(out, size, b64t);
   FILE* file = fopen(filename, "w+");
   int bytes_written = fwrite(out, sizeof(unsigned char), size, file);
   fclose(file);
   // ofstream out(filename);
   // out << s;
   // out.close();
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

pair <unsigned char*,size_t> SignMessage(EVP_PKEY* key, unsigned char* msg, size_t msglen)
{
   EVP_MD_CTX *mdctx = NULL;
   int ret = 0;

   unsigned char* sig;

   /* Create the Message Digest Context */
    if(!(mdctx = EVP_MD_CTX_create()))
    {
      cout << "Creation Failed \n";
    }

   /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key))
    {
      cout << "Sign Init failed \n";
    }
    else
    {
       cout << "Signinit Success \n";
    }
    /* Call update with the message */
    if(1 != EVP_DigestSignUpdate(mdctx, msg, msglen))
    {
      cout << "Sign Update Failed \n";
    }
    else
    {
      cout << "SignUpdate Sucess \n";
    }

    /* Finalise the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
     * signature. Length is returned in slen */
    size_t s_len;

    if(1 != EVP_DigestSignFinal(mdctx, NULL, &s_len))
    {
      cout << "SignFinal Failed \n";
    }
    else
    {
      cout << "SignFinal Sucess \n";
    }
    /* Allocate memory for the signature based on size in slen */
    if(!(sig = (unsigned char*) malloc(s_len) ))
    {
      cout << "Memory Allocation Failed \n";
    }
    /* Obtain the signature */
    if(1 != EVP_DigestSignFinal(mdctx, sig, &s_len))
    {
      cout << "Final Sign Failed \n";
    }

    /* Success */

    cout << "Success! \n";

    /* Clean up */
    if(*sig && !ret) OPENSSL_free(sig);
    if(mdctx) EVP_MD_CTX_destroy(mdctx);

    pair <unsigned char*, size_t> s(sig, s_len);
    return s;
}


int Base64Encode(const unsigned char* buffer, size_t length, char** b64text)
{ //Encodes a binary safe base 64 string
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text=(*bufferPtr).data;

	return (0); //success
}

#endif
