#include <iostream>
#include "RSA.h"

// PRIVATE

EncryptionSequence::ull EncryptionSequence::RSA::CalculateGCD(EncryptionSequence::ull a, EncryptionSequence::ull b)
{
  EncryptionSequence::ull temp;

  //a = abs(a);
  //b = abs(b);

  if (b > a)
  {
    //swap(a, b);
    EncryptionSequence:ull smaller = a;
    a = b;
    b = smaller;
  }

  while (b > 0)
  {
    temp = b;
    b = a % b;
    a = temp;
  }

  return a;
}

// [1 < publicKey < eulerTotient] && gcd(publicKey, eulerTotient) = 1
EncryptionSequence::ull EncryptionSequence::RSA::DetermineValidPublicKey()
{
  EncryptionSequence::ull pubKey = 1 + (rand() % (eulerTotient - 1));

  while (CalculateGCD(pubKey, this->eulerTotient) != 1)
  {
    --pubKey;
  }

  return pubKey;
}

// congruent modulo => privateKey * publicKey == 1 mod eulerTotient, solve for privateKey
EncryptionSequence::ull EncryptionSequence::RSA::DetermineValidPrivateKey()
{
  // just trying to obtain some start value, however, this feels very crackable
  // since the private key's base starts from the public key
  EncryptionSequence::ull privKey = this->publicKey + (rand() % eulerTotient);

  while ((privKey * this->publicKey) % eulerTotient != 1)
  {
    ++privKey;
  }

  return privKey;
}

// ----------

// PUBLIC

EncryptionSequence::RSA::RSA(EncryptionSequence::ull prime0, EncryptionSequence::ull prime1)
{
  this->prime0       = prime0;
  this->prime1       = prime1;
  this->cryptMod     = prime0 * prime1;
  this->eulerTotient = this->cryptMod - (prime0 + prime1 - 1);
  this->publicKey    = this->DetermineValidPublicKey();
  this->privateKey   = this->DetermineValidPrivateKey();
}

// ----------