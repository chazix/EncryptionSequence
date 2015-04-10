/*!
  \author Chase Hutchens

  \brief
    This will attempt to locate 2 prime factors of a larger number.
    The discrepancy with this method is the prime factors must be in the range
    of the 2 <= factor <= ceil(goldenRatio * sqrt(largePrime)). The reason I chose
    to scale by the goldenRatio is because I feel the golden ratio and
    prime numbers go hand in hand.

    Example Values :
        FAST CALCULATION
          25450261 = 5087 * 5003

        LONGER CALCULATION
          3574406403731 = 2750159 * 1299709
*/

#include <iostream>
#include <sstream>
#include <string>
#include <ctime>
#include "PrimeFactorization.h"

static const double goldenRatio = (1.0 + sqrt(5)) / 2.0;

// PRIVATE

/*!
  \param thePrime
    This is our 'F' number that we are trying to prime factor
*/
void EncryptionSequence::PrimeFactor::DeterminePrimes(const ull thePrime)
{
  // initial p'
  ull prime = static_cast<ull>(ceil(goldenRatio * sqrt(thePrime)));

  while (prime > 1)
  {
    // p'
    ull checkPrime = prime;

    // p''
    ull startPrime = static_cast<ull>(ceil(goldenRatio * sqrt(checkPrime)));
    // make sure the startPrime isn't the same as the base prime we're checking against
    startPrime = startPrime == prime ? startPrime - 1 : startPrime;
    bool validPrime = false;

    // determine what is prime
    while (checkPrime % startPrime != 0)
    {
      --startPrime;
      // make sure the startPrime isn't the same as the checkPrime we're comparing
      // the startPrime might initially be greater than the checkPrime
      // (kind of messy)
      startPrime = startPrime == checkPrime ? startPrime - 1 : startPrime;

      if (startPrime == 1)
      {
        validPrime = true;
        break;
      }
    }

    if (validPrime || startPrime == 1)
    {
      this->primes.push_back(checkPrime);
    }

    --prime;

    // a prime is never even, but a prime is 2
    while (prime % 2 == 0 && prime != 2)
      --prime;
  }

  std::cout << "\nFound : " << this->primes.size() << " Primes That May Make Up " << thePrime << "\n";
}

// END PRIVATE

// PUBLIC

void EncryptionSequence::PrimeFactor::FactorPrime(const ull toFactorPrime, const int charLen)
{
  std::stringstream greatestDigit;
  greatestDigit << toFactorPrime;

  DeterminePrimes(toFactorPrime);

  time_t startTime;
  time(&startTime);

  unsigned foundPrimes = this->primes.size();

  for (unsigned i = 0; i < foundPrimes; ++i)
  {
    ull prime = this->primes[i];
    bool broke = false;
    for (unsigned j = i; j < foundPrimes; ++j)
    {
      ull primeVal = prime * this->primes[j];

      // This causes noticeable slowdown instead of just elapsing
      /*if (charLen != 0)
      {
        std::stringstream ss;
        ss << primeVal;

        // not going to be any other larger primes beyond this one
        // multiplied with this one
        if (ss.str().size() != charLen)
        {
          break;
          broke = true;
        }
      }*/

      // we've eliminated what we don't want

      //std::cout << primeVal << " | " << prime << " * " << primes[j] << std::endl;

      // 5087 * 5003 (etc..)
      if (primeVal == toFactorPrime)
      {
        time_t endTime;
        time(&endTime);
        double timeTaken = difftime(endTime, startTime);

        std::cout << "\nFound Prime Factors : [p] = " << prime << " | [q] = " << this->primes[j] << std::endl;
        std::cout << "Time Taken To Factor Prime : " << timeTaken << " seconds" << std::endl;

        return;
      }
    }
  }

  std::cout << "\nFound : No Two Primes That Make Up : " << toFactorPrime << std::endl;
}

// END PUBLIC

void EncryptionSequence::DoPrimeFactor()
{
  std::string inputNumber, foundNumber;
  std::cout << "What Number Do You Want To Factor?\n:";
  std::getline(std::cin, inputNumber);

  // parse the inputted number for only numbers
  unsigned stringSize = inputNumber.size();
  for (unsigned i = 0; i <= stringSize; ++i)
  {
    if ((inputNumber[i] >= '0' && inputNumber[i] <= '9'))
    {
      foundNumber += inputNumber[i];
    }
  }

  EncryptionSequence::PrimeFactor pFactor;
  pFactor.FactorPrime(std::stoull(foundNumber), stringSize);

  std::cout << "\nPress Enter To Continue";
  getchar();
}