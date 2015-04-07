#include <iostream>
#include <sstream>   /* stringstream */
#include <algorithm> /* transform */
#include "RSA.h"

// DATA DEFINITION

// tilde represents unknown character
// index number represents id byte for usage during encryption
// just need to make sure to keep everything the size of the padScheme
static EncryptionSequence::byte dataValues[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
                                                 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                                                 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7',
                                                 '8', '9', '0', '-', '=', '!', '@', '#', '$', '%', '^',
                                                 '&', '*', '(', ')', '_', '+', ':', ';', '"', ',', '.',
                                                 '?', ' ', '~' };

static const unsigned sizeOfDataValues = sizeof(dataValues) / sizeof(dataValues[0]);

// ----------

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

EncryptionSequence::ull EncryptionSequence::RSA::CalculatePow(EncryptionSequence::ull a, EncryptionSequence::ull p)
{
  EncryptionSequence::ull val = a;

  for (EncryptionSequence::ull i = 1; i < p; ++i)
  {
    val *= a;
  }

  return val;
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

unsigned EncryptionSequence::RSA::RetrieveDataValue(char data)
{
  for (unsigned i = 0; i < sizeOfDataValues; ++i)
  {
    if (data == dataValues[i])
    {
      return i;
    }
  }

  // return the unknown character index
  return sizeOfDataValues - 1;
}

// parses to numbers of length padScheme
std::vector<EncryptionSequence::ull> EncryptionSequence::RSA::ParseToNumbers(const std::string& data)
{
  // I need to parse the data to a number where each number is 2 digits

  std::vector<EncryptionSequence::ull> datas;
  std::stringstream stream;
  bool first = true;
  unsigned size = 0;

  std::string upperData = data;
  std::transform(upperData.begin(), upperData.end(), upperData.begin(), ::toupper);
  unsigned dataSize = data.size();
  for (unsigned i = 0; i < dataSize; ++i)
  {
    unsigned val = RetrieveDataValue(upperData[i]);
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

      first     = true;
      size      = 0;
      stream.str(std::string()); // clear stream
    }
  }

  return datas;
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
EncryptionSequence::RSA::RSA(EncryptionSequence::ull prime0, EncryptionSequence::ull prime1, int padScheme)
{
  this->padScheme    = padScheme;
  this->prime0       = prime0;
  this->prime1       = prime1;
  this->cryptMod     = prime0 * prime1;
  this->eulerTotient = this->cryptMod - (prime0 + prime1 - 1);
  this->publicKey    = this->DetermineValidPublicKey();
  this->privateKey   = this->DetermineValidPrivateKey();

  std::cout << "Test Pow\n";
  std::cout << this->CalculatePow(2, 1) << std::endl;

  std::cout << "Test Encrypt\n";
  this->EncryptData("Testing Interesting Things");
}

/*
  1) process message into individual bytes of length padScheme
    - M into m => [0 <= m < cryptMod]
  2) encrypt message
    - congruent modulo => encrypted_message == m^publicKey mod cryptMod
      - note: at least 9 values of m will result in encrypted_message equal to m
*/
void EncryptionSequence::RSA::EncryptData(const std::string& toEncrypt)
{
  std::vector<EncryptionSequence::ull> toCryptPieces = this->ParseToNumbers(toEncrypt);
  std::vector<EncryptionSequence::ull> encryptedPieces;

  for (auto& cryptPiece : toCryptPieces)
  {
    EncryptionSequence::ull crypt = this->CalculatePow(cryptPiece, this->publicKey) % this->cryptMod;
    encryptedPieces.push_back(crypt);
  }
}

void EncryptionSequence::DoRSA()
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
  RSA(569, 991, 2);

  std::cout << "\nPress Enter To Continue";
  getchar();
}

// ----------