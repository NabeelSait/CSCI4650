#include <iostream>
#include <utility>
#include <new>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

#include "CryptoFunctions.h"

using namespace std;

string base64_encode(unsigned char* bytes_to_encode, size_t in_len) {

  string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

  string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;
}

int DESencrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        fprintf(stderr, "Ctx Faliure");

    cout << "CTX succeeded" << "\n";

    if(1 != EVP_EncryptInit_ex(ctx, EVP_des_cfb(), NULL, key, iv))
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

int DESdecrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        cout << "CTX creation failed \n";
    }
    else
    {
        cout << "CTX creation succeeded \n";
    }
    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_des_cfb(), NULL, key, iv))
    {
        cout << "Initiation Failed \n";
    }
    else
        cout << "Initiation Succeeded \n";

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        cout << "Update Failed \n";
    }
    else
    {
      cout << "Update Success! \n";
   }
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        cout << "Decryption Failed \n";
        ERR_print_errors_fp(stderr);
     }
    else
        cout << "Decryption Success! \n";

    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void FiletoChar(const char* filename, size_t size, unsigned char* c, size_t* clen)
{
   FILE* file = fopen(filename, "r+");
   *clen = fread(c, sizeof(unsigned char), size, file);
   fclose(file);
}

void Chartob64File(unsigned char* out, size_t size, string filename)
{
   string s = base64_encode(out, size);
   ofstream file(filename.c_str());
   file << s;
   file.close();
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

RSA * createRSA(unsigned char * key)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
    }

    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }

    return rsa;
}

int public_decrypt(unsigned char * enc_data, int data_len, const char* filename, unsigned char *decrypted)
{
    int padding = RSA_NO_PADDING;
    FILE * fp = fopen(filename,"rb");
    if(fp == NULL)
    {
       printf("Unable to open file %s \n",filename);
    }
    RSA* rsa = NULL;
    rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    RSA_free(rsa);
    return result;
}

void SignMessage(EVP_PKEY* key, unsigned char* msg, size_t msglen, unsigned char* sig, size_t* s_len)
{
   EVP_MD_CTX *mdctx = NULL;
   int ret = 0;
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
    if(1 != EVP_DigestSignFinal(mdctx, NULL, s_len))
    {
      cout << "SignFinal Failed \n";
    }
    else
    {
      cout << "SignFinal Sucess \n";
    }
    /* Allocate memory for the signature based on size in slen */
    if(!(sig = (unsigned char*) malloc(*s_len) ))
    {
      cout << "Memory Allocation Failed \n";
    }
    /* Obtain the signature */
    if(1 != EVP_DigestSignFinal(mdctx, sig, s_len))
    {
      cout << "Final Sign Failed \n";
    }
    /* Success */
    cout << "Success! \n";
    /* Clean up */
    if(*sig && !ret) OPENSSL_free(sig);
    if(mdctx) EVP_MD_CTX_destroy(mdctx);
}

void EnvelopeOpen(const char* ek_file, const char* TPpubkey, unsigned char* plaintext, size_t p_len)
{

   size_t size = getFileByteSize(ek_file);
   unsigned char* ek = (unsigned char *) malloc(size);
   size_t eklen;
   FiletoChar(ek_file, size, ek, &eklen);

   EVP_PKEY* pPubKey  = NULL;
   FILE*     pFile    = NULL;
   unsigned char out[4098]={};

   size_t outlen = public_decrypt(ek, eklen, TPpubkey, out);

   ChartoFile(out, outlen, "test_key.key");
   Chartob64File(out, outlen, "test_key.txt");

   cout << "Decryption Success \n";

   unsigned char ciphertext[4098]={};

   ChartoFile(plaintext, p_len, "test.txt");
   DESencrypt(plaintext, p_len, out, NULL, ciphertext);
   cout << "Encryption Success \n";
   size_t c_len = strlen ((char*)ciphertext);
   ChartoFile(ciphertext, c_len, "ciphertext.txt");

   free(ek);
}

void SignPlaintext(unsigned char* plaintext, size_t p_len, const char* TPprivkey)
{
   EVP_PKEY* pPrivKey;
   FILE* pFile;

   if((pFile = fopen("privkey.pem","rt")) && (pPrivKey = PEM_read_PrivateKey(pFile,NULL,NULL,NULL)))
   {
      fprintf(stderr,"Private key read.\n");
   }
   else
   {
      fprintf(stderr,"Cannot read \"privkey.pem\".\n");
   }
   fclose(pFile);
   // SignMessage(pPrivKey, plaintext, p_len, sig, &slen);
    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;
   /* Create the Message Digest Context */
    if(!(mdctx = EVP_MD_CTX_create()))
    {
      cout << "Creation Failed \n";
    }

   /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pPrivKey))
    {
      cout << "Sign Init failed \n";
    }
    else
    {
       cout << "Signinit Success \n";
    }
    /* Call update with the message */
    if(1 != EVP_DigestSignUpdate(mdctx, plaintext, p_len))
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
    unsigned char* sig = (unsigned char*) malloc(s_len);
    if(!(sig))
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
   if(mdctx) EVP_MD_CTX_destroy(mdctx);

   Chartob64File(sig, s_len, "signature.txt");
   ChartoFile(sig, s_len, "binary_signature.txt");
   free(sig);
   EVP_PKEY_free(pPrivKey);
}

void DecryptPlaintext(const char* c_file, const char* sk_file)
{
   size_t size = getFileByteSize(c_file);
   unsigned char* ciphertext = (unsigned char *) malloc(size);
   size_t c_len;

   FiletoChar(c_file, size, ciphertext, &c_len);

   if (!(c_len >= 0))
      cout << "Ciphertext loading failed \n";
   else
      cout << "Ciphertext loaded Succesfully! \n";

   size = getFileByteSize(sk_file);
   unsigned char* key = (unsigned char *) malloc(size);
   size_t keylen;
   FiletoChar(sk_file, size, key, &keylen);

   if (!(keylen >= 0))
      cout << "Session key loading failed \n";
   else
      cout << "Session Key loaded Successfully! \n";

   cout << keylen << "\n";
   unsigned char plaintext[c_len];

   size_t p_len = DESdecrypt(ciphertext, c_len, key, NULL, plaintext);

   plaintext[p_len] = '\0';

   /* Show the decrypted text */
   printf("Decrypted text is:\n");
   printf("%s\n", plaintext);

   ChartoFile(plaintext, p_len, "decrypted.txt");
   free(key);
   free(ciphertext);
}

void VerifySign(const char* p_file, const char* s_file, const char* pk_file)
{
   size_t size = getFileByteSize(s_file);
   unsigned char* sig = (unsigned char *) malloc(size);
   size_t s_len;
   FiletoChar(s_file, size, sig, &s_len);

   FILE* pFile = fopen(pk_file,"rt");
   EVP_PKEY* pPubKey = PEM_read_PUBKEY(pFile,NULL,NULL,NULL);
   fclose(pFile);

   EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

   size = getFileByteSize(p_file);
   unsigned char* m = (unsigned char *) malloc(size);
   size_t m_len;

   FiletoChar(p_file, size, m, &m_len);
   /* Initialize `key` with a public key */
   if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pPubKey))
   {
      cout << "Verify Initiation Error \n";
   }
/* Initialize `key` with a public key */
   if(1 != EVP_DigestVerifyUpdate(mdctx, m, m_len))
   {
      cout << "Verify Update Error \n";
   }

   if(1 == EVP_DigestVerifyFinal(mdctx, sig, s_len))
   {
      cout << "Verification Success! \n";
   }
   else
   {
      cout << "Verification Failiure \n";
   }
   free(m);
   free(sig);
   EVP_MD_CTX_destroy(mdctx);
   EVP_PKEY_free(pPubKey);
}
