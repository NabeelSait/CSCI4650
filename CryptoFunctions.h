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


using namespace std;

#ifndef CRYPTO_FUNCTIONS_H
#define CRYPTO_FUNCTIONS_H

string base64_encode(unsigned char* bytes_to_encode, size_t in_len);

int DESencrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

int DESdecrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                        unsigned char *iv, unsigned char *plaintext);

void FiletoChar(const char* filename, size_t size, unsigned char* c, size_t* clen);

void Chartob64File(unsigned char* out, size_t size, string filename);

void ChartoFile(unsigned char* out, size_t size, const char* filename);

size_t getFileByteSize(const char* filename);

RSA * createRSA(unsigned char * key);

int public_decrypt(unsigned char * enc_data, int data_len, const char* filename, unsigned char *decrypted);

void SignMessage(EVP_PKEY* key, unsigned char* msg, size_t msglen, unsigned char* sig, size_t* s_len);

void EnvelopeOpen(const char* ek_file, const char* TPpubkey, unsigned char* plaintext, size_t p_len);

void SignPlaintext(unsigned char* plaintext, size_t p_len, const char* TPprivkey);

void DecryptPlaintext(const char* c_file, const char* sk_file);

void VerifySign(const char* p_file, const char* s_file, const char* pk_file);

#endif
