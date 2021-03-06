#ifndef _PRIME_FACTORIZATION_H_INCLUDED_
#define _PRIME_FACTORIZATION_H_INCLUDED_

#include <vector>
#include <cstdint>

namespace EncryptionSequence
{
  typedef uint64_t ull;

  class PrimeFactor
  {
    private:
      std::vector<ull> primes;

      void DeterminePrimes(const ull thePrime);

    public:
      void FactorPrime(const ull toFactorPrime, const int charLen = 0);
      ull P, Q;
  };

  // Implementation of the PrimeFactor Behavior
  void DoPrimeFactor();
}

#endif