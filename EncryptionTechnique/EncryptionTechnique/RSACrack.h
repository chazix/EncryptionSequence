#include <thread>
#include "PrimeFactorization.h"
#include "RSA.h"
#include <iostream>
#include <sstream>

namespace EncryptionSequence{

  void CrackRSA();

  // Return is the decryption key
  // N is the product (p - 1)(q - 1)
  ull InverseMod(ull PublicKey, ull N);

}