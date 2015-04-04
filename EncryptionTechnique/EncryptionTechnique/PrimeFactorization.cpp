#include <iostream>
#include <vector>
#include <sstream>
#include <string>
#include <fstream>
#include <conio.h>
#include <ctime>
#include <utility>

std::vector<int> primes;
std::vector<std::pair<int, int> > possibleVals;
double goldenRatio = (1.0 + sqrt(5)) / 2.0;

void determinePrimes(const int thePrime, std::vector<int>& primePlace)
{
  int prime = static_cast<int>(ceil(goldenRatio * sqrt(thePrime)));

  while (prime > 1)
  {
    int checkPrime = prime;

    int startPrime  = static_cast<int>(ceil(goldenRatio * sqrt(checkPrime)));
    bool validPrime = false;

    // determine what is prime
    while (checkPrime % startPrime != 0)
    {
      --startPrime;

      if (startPrime == 1)
      {
        validPrime = true;
        break;
      }
    }

    if (validPrime)
    {
      primes.push_back(checkPrime);
    }

    --prime;

    // a prime is never even
    while (prime % 2 == 0)
      --prime;
  }

  std::cout << "Found : " << primes.size() << " Primes That May Make Up " << thePrime << "\n";
}

void FactorPrime(const int toFactorPrime, const int charLen)
{
  std::stringstream greatestDigit;
  greatestDigit << toFactorPrime;

  determinePrimes(toFactorPrime, primes);

  time_t startTime;
  time(&startTime);

  for (unsigned i = 0; i < primes.size(); ++i)
  {
    int prime = primes[i];
    for (unsigned j = i; j < primes.size(); ++j)
    {
      int primeVal = prime * primes[j];
      std::stringstream ss;
      ss << primeVal;

      // not going to be any other larger primes beyond this one
      // multiplied with this one
      if (ss.str().size() != charLen)
      {
        break;
      }

      // we've eliminated what we don't want

      //std::cout << primeVal << " | " << prime << " * " << primes[j] << std::endl;

      // 5087 * 5003 (etc..)
      if (primeVal == toFactorPrime)
      {
        time_t endTime;
        time(&endTime);
        double timeTaken = difftime(endTime, startTime);

        std::cout << "Found Prime Factors : [p] = " << prime << " | [q] = " << primes[j] << std::endl;
        std::cout << "Time Taken To Factor Prime : " << timeTaken << " seconds" << std::endl;

        return;
      }
    }
  }
}

int main(int argc, char* argv[])
{
  return 0;
}