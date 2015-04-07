#include <iostream>
#include <sstream>   /* stringstream */
#include <algorithm> /* transform */
#include "RSA.h"

namespace EncryptionSequence
{
  // DATA DEFINITION

  // tilde represents unknown character
  // index number represents id byte for usage during encryption
  // just need to make sure to keep everything the size of the padScheme
  static const byte dataValues[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
                                     'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                                     'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', '0', '-', '=', '!', '@', '#', '$', '%', '^',
                                     '&', '*', '(', ')', '_', '+', ':', ';', '"', ',', '.',
                                     '?', ' ', '~' };

  static const unsigned sizeOfDataValues = sizeof(dataValues) / sizeof(dataValues[0]);

  // ----------

  // PRIVATE

  ull RSA::CalculateGCD(ull a, ull b)
  {
    ull temp;

    //a = abs(a);
    //b = abs(b);

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

  // http://en.wikipedia.org/wiki/Modular_exponentiation
  ull RSA::CalculateModularPow(const ull base, const ull exp, const ull mod)
  {
    ull val = 1;
    for (ull e = 1; e <= exp; ++e)
    {
      val = (val * base) % mod;
    }

    return val;
  }

  // [1 < publicKey < eulerTotient] && gcd(publicKey, eulerTotient) = 1
  ull RSA::DetermineValidPublicKey()
  {
    ull pubKey = 1 + (rand() % (eulerTotient - 1));

    while (CalculateGCD(pubKey, this->eulerTotient) != 1)
    {
      --pubKey;
    }

    return pubKey;
  }

  // congruent modulo => privateKey * publicKey == 1 mod eulerTotient, solve for privateKey
  ull RSA::DetermineValidPrivateKey()
  {
    // just trying to obtain some start value, however, this feels very crackable
    // since the private key's base starts from the public key
    ull privKey = this->publicKey + (rand() % eulerTotient);

    while ((privKey * this->publicKey) % eulerTotient != 1)
    {
      ++privKey;
    }

    return privKey;
  }

  unsigned RSA::ByteDataValueToNum(const byte value)
  {
    for (unsigned i = 0; i < sizeOfDataValues; ++i)
    {
      if (value == dataValues[i])
      {
        return i;
      }
    }

    // return the unknown character index
    return sizeOfDataValues - 1;
  }

  byte RSA::NumValueToByteData(const unsigned value)
  {
    // might want to mod value by the sizeOfDataValues to avoid a potential crash
    return dataValues[value];
  }

  // parses to numbers of length padScheme
  std::vector<ull> RSA::ParseToNumbers(const std::string& data)
  {
    // I need to parse the data to a number where each number is 2 digits

    std::vector<ull> datas;
    std::stringstream stream;
    bool first = true;
    unsigned size = 0;

    std::string upperData = data;
    std::transform(upperData.begin(), upperData.end(), upperData.begin(), ::toupper);
    unsigned dataSize = data.size();
    for (unsigned i = 0; i < dataSize; ++i)
    {
      unsigned val = ByteDataValueToNum(upperData[i]);
      if (val < 10 && !first) // not a two digit and not first
      {
        stream << '0';
        stream << val;
      }
      else
      {
        stream << val;
        first = false;
      }
      
      if (++size == this->padScheme || i == dataSize - 1)
      {
        // end will never be reached because we will stay within our ull size boundary
        char* end = 0;
        datas.push_back(std::strtoull(stream.str().c_str(), &end, 10));

        first = true;
        size = 0;
        stream.str(std::string()); // clear stream
      }
    }

    return datas;
  }

  // converts the std::vector<ull> to the byte string data
  std::string RSA::ParseToData(const std::vector<ull>& decryptedData)
  {
    std::string convertedData;

    for (auto data : decryptedData)
    {
      std::stack<byte> foundDecryptedData;
      std::stringstream stream;
      stream << data;
      std::string number = stream.str();
      
      // we are traversing in reverse order
      // each value consists of two digits
      // => unless it is the last digit
      for (auto it = number.rbegin(); it != number.rend(); it += 2)
      {
        std::string foundValue;

        if (it + 1 == number.rend()) // last digit
        {
          foundValue += *it;
          foundDecryptedData.push(this->NumValueToByteData(std::stoi(foundValue)));
          break;
        }
        else
        {
          foundValue += *(it + 1);
          foundValue += *it;
          foundDecryptedData.push(this->NumValueToByteData(std::stoi(foundValue)));
        }
      }

      // need to reorder
      while (!foundDecryptedData.empty())
      {
        convertedData += foundDecryptedData.top();
        foundDecryptedData.pop();
      }
    }

    return convertedData;
  }

  // ----------

  // PUBLIC

  /*****************************************************************************/
  /*!
    \param prime0
    The first prime

    \param prime1
    The second prime

    \param padScheme
    The size of each message block : needs to be in range (0, cryptMod),
    ideally a mid range
    */
  /*****************************************************************************/
  RSA::RSA(ull prime0, ull prime1, int padScheme)
  {
    this->padScheme = padScheme;
    this->prime0 = prime0;
    this->prime1 = prime1;
    this->cryptMod = prime0 * prime1;
    this->eulerTotient = this->cryptMod - (prime0 + prime1 - 1);
    this->publicKey = this->DetermineValidPublicKey();
    this->privateKey = this->DetermineValidPrivateKey();

    std::cout << "Test Pow\n";
    std::cout << this->CalculateModularPow(27856, 5689, 563879) << std::endl;

    std::cout << "Test Encrypt\n";
    auto encrypted = this->EncryptData("Testing Interesting Things");
    auto decrypted = this->DecryptData(encrypted);
  }

  /*
    1) process message into individual bytes of length padScheme
      - M into m => [0 <= m < cryptMod]
    2) encrypt message
      - congruent modulo => encrypted_message == m^publicKey mod cryptMod
        - note: at least 9 values of m will result in encrypted_message equal to m
    */
  std::vector<ull> RSA::EncryptData(const std::string& toEncrypt)
  {
    std::vector<ull> toCryptPieces = this->ParseToNumbers(toEncrypt);
    std::vector<ull> encryptedPieces;

    for (auto& cryptPiece : toCryptPieces)
    {
      ull crypt = this->CalculateModularPow(cryptPiece, this->publicKey, this->cryptMod);
      encryptedPieces.push_back(crypt);
    }

    return encryptedPieces;
  }

  std::string RSA::DecryptData(const std::vector<ull>& toDecrypt)
  {
    std::vector<ull> decryptedPieces;
    for (auto& cryptPiece : toDecrypt)
    {
      ull decrypt = this->CalculateModularPow(cryptPiece, this->privateKey, this->cryptMod);
      decryptedPieces.push_back(decrypt);
    }

    std::string decryptedData = this->ParseToData(decryptedPieces);

    return decryptedData;
  }

  void DoRSA()
  {
    /*std::string inputNumber, foundNumber;
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
    pFactor.FactorPrime(std::stoull(foundNumber), stringSize);*/

    std::cout << "Testing RSA\n";
    RSA(569, 991, 3);

    std::cout << "\nPress Enter To Continue";
    getchar();
  }

  // ----------
}