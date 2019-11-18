#include <iostream>
#include <utility>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
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
   const char* p_file;
   const char* ek_file;
   const char * tpub_file;
   const char* priv_file;
   //Argument Parsing
   for (int i = 1; i < argc; ++i)
   {
      string arg = argv[i];
      if ((arg == "-k") || (arg == "--key"))
      {
         if (i + 1 < argc)
         {
            ek_file = argv[i+1];
            cout << "Session key: " << ek_file << "\n";
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
              tpub_file = argv[i+1];
              cout << "Publickey: " << tpub_file << "\n";
           }
      }
      else if ((arg == "-r") || (arg == "--privatekey"))
      {
           if (i + 1 < argc)
           {
              priv_file = argv[i+1];
              cout << "Private Key: " << priv_file << "\n";
           }
      }
   }



   size_t size = getFileByteSize(p_file);
   unsigned char * plaintext = (unsigned char *) malloc(size);
   size_t p_len;
   FiletoChar(p_file, size, plaintext, &p_len);
   EnvelopeOpen(ek_file, tpub_file, plaintext, p_len);
   // EncryptPlaintext(out, outlen, plaintext, *p_len);

   SignPlaintext(plaintext, p_len, priv_file);
   free(plaintext);
}
