/*!
  \author Chase Hutchens

  \brief
    RSA object definitions utilizing unsigned long long and std::string
*/

#ifndef _RSA_H_INCLUDED_
#define _RSA_H_INCLUDED_

#include <stack>
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
      ull CalculateModularPow(const ull base, const ull exp, const ull mod);
      ull DetermineValidPublicKey();
      ull DetermineValidPrivateKey();
      unsigned ByteDataValueToNum(const byte value);
      byte NumValueToByteData(const unsigned value);

      std::string ParseToData(const std::vector<ull>& decryptedData);

    public:
      RSA(const ull prime0, const ull prime1, const int padScheme);
      /*
        process message into individual bytes of length padScheme
        - M into m => [0 <= m < cryptMod]
      */
      std::vector<ull> ParseToNumbers(const std::string& data);
      /*
        1) process message into individual bytes of length padScheme
            - M into m => [0 <= m < cryptMod]
        2) encrypt message
            - congruent modulo => encrypted_message == m^publicKey mod cryptMod
                - note: at least 9 values of m will result in encrypted_message equal to m
      */
      std::vector<ull> EncryptData(const std::string& toEncrypt);
      /*
        1) congruent modulo => decrypted_message == encrypted_message^privateKey mod cryptMod
        2) reverse the pad scheme
      */
      std::string DecryptData(const std::vector<ull>& toDecrypt);
  };

  void DoRSA();
}

#endif