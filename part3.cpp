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

   const char* c_file;
   const char* sk_file;
   const char * iv_file;
   const char* sig_file;
   const char* p_file;
   const char* pubk_file;
   //Argument Parsing
   for (int i = 1; i < argc; ++i)
   {
      string arg = argv[i];
      if ((arg == "-c") || (arg == "--ciphertext"))
      {
         if (i + 1 < argc)
         {
            c_file = argv[i+1];
            cout << "ciphertext: " << c_file << "\n";
         }
      }
      else if ((arg == "-p") || (arg == "--plaintext"))
      {
           if (i + 1 < argc)
           {
              p_file = argv[i+1];
              cout << "Plaintext: " << p_file << "\n";
           }
      }
      else if ((arg == "-b") || (arg == "--publickey"))
      {
           if (i + 1 < argc)
           {
              pubk_file = argv[i+1];
              cout << "Publickey: " << pubk_file << "\n";
           }
      }
      else if ((arg == "-k") || (arg == "--sessionkey"))
      {
           if (i + 1 < argc)
           {
              sk_file = argv[i+1];
              cout << "Session Key: " << sk_file << "\n";
           }
      }
      else if ((arg == "-i") || (arg == "--iv"))
      {
           if (i + 1 < argc)
           {
              iv_file = argv[i+1];
              cout << "IV: " << iv_file << "\n";
           }
      }
      else if ((arg == "-s") || (arg == "--signature"))
      {
           if (i + 1 < argc)
           {
              sig_file = argv[i+1];
              cout << "Signature: " << sig_file << "\n";
           }
      }
   }

   DecryptPlaintext(c_file, sk_file, iv_file);
   VerifySign(p_file, sig_file, pubk_file);
}
