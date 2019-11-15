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
   DecryptPlaintext("ciphertext.txt", "session_key.key");
   VerifySign("plaintext.txt", "binary_signature.txt", "pubkey.pem");
}
