#include <iostream>
#include <string>
#include <ctime>

#include "PrimeFactorization.h"
#include "RSA.h"

int main(int argc, char** argv)
{
  srand(time(0));
  int option = -1;

  while (option != 0)
  {
    std::cout << " ----------------------\n";
    std::cout << "|  Input Options       |\n";
    std::cout << " ----------------------\n";
    std::cout << "| 0 : Exit             |\n";
    std::cout << "| 1 : Factor Prime     |\n";
    std::cout << "| 2 : RSA Encryption   |\n";
    std::cout << " ----------------------\n: ";

    std::string desiredTestValue;
    std::getline(std::cin, desiredTestValue);
    option = std::stoi(desiredTestValue);

    switch (option)
    {
      case (1) :
      {
        EncryptionSequence::DoPrimeFactor(); // 25450261 | 5087 & 5003
                                             // 2545061  | 1993 & 1277
        break;
      }

      case (2) :
      {
        EncryptionSequence::DoRSA();
        break;
      }

      default:
        break;
    }

    system("cls");
  }

  return 0;
}