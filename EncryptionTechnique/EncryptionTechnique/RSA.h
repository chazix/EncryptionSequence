#ifndef _RSA_H_INCLUDED_
#define _RSA_H_INCLUDED_

#include "PrimeFactorization.h"

namespace EncryptionSequence
{
  typedef char byte;

  class RSA
  {
    private:
      int padScheme;
      ull prime0, prime1;
      ull cryptMod;     // = prime0 * prime1
      ull eulerTotient; // = cryptMod - (prime0 + prime1 - 1)
      ull publicKey;    // = [1 < publicKey < eulerTotient] && gcd(publicKey, eulerTotient) = 1
      ull privateKey;   // = congruent modulo => privateKey * publicKey == 1 mod eulerTotient, solve for privateKey
      
    private:
      ull CalculateGCD(ull a, ull b);
      ull CalculatePow(ull a, ull p);
      ull DetermineValidPublicKey();
      ull DetermineValidPrivateKey();
      unsigned RetrieveDataValue(char data);
      std::vector<ull> ParseToNumbers(const std::string& data);

    public:
      RSA(ull prime0, ull prime1, int padScheme);
      /*
        1) process message into individual bytes of length padScheme
            - M into m => [0 <= m < cryptMod]
        2) encrypt message
            - congruent modulo => encrypted_message == m^publicKey mod cryptMod
                - note: at least 9 values of m will result in encrypted_message equal to m
      */
      void EncryptData(const std::string& toEncrypt);
      /*
        1) congruent modulo => decrypted_message == encrypted_message^privateKey mod cryptMod
        2) reverse the pad scheme
      */
      void DecryptData(byte** message);
  };

  void DoRSA();
}

#endif