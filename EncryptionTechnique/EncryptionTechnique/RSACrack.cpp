#include "RSACrack.h"

namespace EncryptionSequence{

  bool Isprime(ull posPrime)
  {
    ull range = sqrtl(posPrime);
    for (ull i = 2; i <= range; ++i)
    {
      if (posPrime % i == 0)
        return false;
    }
    return true;
  }

ull calcGCD(ull a, ull b)
{
  ull temp;

  if (b > a)
  {
    //swap(a, b);
    ull smaller = a;
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

long long inverseMod(long long a, long long b)
{
  if (b == 1)
    return 1;

  long long tempB = b;
  long long q, r;
  long long x0 = 0;
  long long x1 = 1;
  while (a > 1)
  {
    if (b == 0)
      return 0;
    q = a / b;
    r = b;
    b = a % b;
    a = r;
    r = x0;
    x0 = x1 - q * x0;
    x1 = r;
  }

  if (x1 < 0)
    x1 += tempB;

  return x1;

}

ull generateValidPublicKey(ull prime0, ull prime1)
{
  ull eulerTotient = prime0 * prime1 - (prime0 + prime1 - 1);
  ull pubKey = 1 + (rand() % (eulerTotient - 1));

  while (calcGCD(pubKey, eulerTotient) != 1)
  {
    --pubKey;
  }

  return pubKey;
}

void CrackRSA()
{
  system("cls");

  std::cout << " ----------------------\n";
  std::cout << "|  Cracking   Options  |\n";
  std::cout << " ----------------------\n";
  std::cout << "| 0 : Return To Main   |\n";
  std::cout << "|     Calc Private Key |\n";
  std::cout << "| 1 : Given N          |\n";
  std::cout << "| 2 : Given Public Key |\n";
  std::cout << " ----------------------\n:";
  
  std::string Value;
  std::getline(std::cin, Value);
  int option = std::stoi(Value);
  std::string N, PublicKeyString;
  ull publicKey, privKey;
  PrimeFactor pFactor;

  switch (option)
  {
  default :
    return;

  case(1) :
    std::cout << std::string(23, '=') << std::endl;

    std::cout << "Input the product of large primes (N)\n:";
    std::getline(std::cin, N);

    std::cout << "Factoring N:\n";
    pFactor.FactorPrime(std::stoull(N));

    if (pFactor.P == 0)
    {
      std::cout << "\n Cannot compute Private Key, N is not factorable.";
      std::cout << "\nPress enter to continue...";
      getchar();
      break;
    }

    publicKey = generateValidPublicKey(pFactor.P, pFactor.Q);

    std::cout << "Valid Public Key generated: " << publicKey << std::endl;

    std::cout << "\n"
      << "Calculating Private Key..." << std::endl;
     
    privKey = inverseMod(publicKey, (long long)((pFactor.P - 1) * (pFactor.Q - 1)));

    if (privKey)
      std::cout << "\n" << "Private Key found : " << privKey << std::endl;
    else
      std::cout << "\n" << "Could not find a valid private key, Public Key and (P - 1)*(Q - 1) are not coprime " << privKey << std::endl;

    std::cout << "\nPress enter to continue...";
    getchar();

    break;

  case(2) :
    std::cout << std::string(23, '=') << std::endl;

    std::cout << "Input Public Key (e)\n:";
    std::getline(std::cin, PublicKeyString);
    publicKey = std::stoull(PublicKeyString);

    std::cout << "Input the product of large primes (N)\n:";
    std::getline(std::cin, N);
    
    std::cout << "Factoring N:\n";
    pFactor.FactorPrime(std::stoull(N));
    
    if (pFactor.P == 0)
    {
      std::cout << "\n Cannot compute Private Key, N is not factorable.";
      std::cout << "\nPress enter to continue...";
      getchar();
      break;
    }

    std::cout << "\n"
      << "Calculating Private Key..." << std::endl;

    privKey = inverseMod(publicKey, (long long)((pFactor.P - 1) * (pFactor.Q - 1)));

    if (privKey)
      std::cout << "\n" << "Private Key found : " << privKey << std::endl;
    else
      std::cout << "\n" << "Could not find a valid private key, Public Key and (P - 1)*(Q - 1) are not coprime " << privKey << std::endl;

    std::cout << "\nPress enter to continue...";
    getchar();
    break;
  }
  
}
}