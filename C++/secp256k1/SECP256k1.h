#ifndef SECP256K1H
#define SECP256K1H

#include "Point.h"
#include <string>
#include <vector>

// Address type
#define P2PKH  0
#define P2SH   1
#define BECH32 2

class Secp256K1 {

public:

  Secp256K1();
  ~Secp256K1();
  void Init();
  Point ComputePublicKey(Int *privKey);
  Point NextKey(Point &key);
  bool  EC(Point &p);

  void GetHash160(int type, bool compressed, Point &pubKey, unsigned char *hash);
  std::string GetHashFromP2PKHAddress(char* address);
  std::string GetAddressFromPub(int type, bool compressed, Point &pubKey);
  std::string GetAddressFromHash(int type, bool compressed, unsigned char *hash160);
  std::string GetBech32Address(Point &pubKey);
  std::string GetBech32P2WSHAddress(Point &pubKey);
  std::string GetPrivAddress(bool compressed, Int &privKey);
  std::string GetPublicKeyHex(bool compressed, Point &p);
  Point ParsePublicKeyHex(std::string str, bool &isCompressed);
  Point ParsePublicKeyHex2(char* pubkey);
  void GetPubKeyBytes(bool compressed, Point& pubKey, unsigned char* publicKeyBytes);
  Point SetPubKeyBytes(unsigned char* publicKeyBytesIn);
  void GetXBytes(bool compressed, Point& pubKey, unsigned char* publicKeyBytes);

  bool CheckPudAddress(std::string address);

  static Int DecodePrivateKey(char *key, bool *compressed);
  static Int DecodePrivateKey2(char *key);
  static Int GetYToX(Int x, bool isEven);
  
  Point PointMultiplication(Point &P, Int *scalar);
  Point Add(Point &p1, Point &p2);
  Point Add2(Point &p1, Point &p2);
  Point AddDirect(Point &p1, Point &p2);
  Point AddPoints(Point &p1, Point &p2);
  Point AddPoints2(Point &p1, Point &p2);
  Point SubtractPoints(Point &p1, Point &p2);
  Point SubtractPoints2(Point &p1, Point &p2);
  Point Double(Point &p);
  Point DoubleDirect(Point &p);

  Point G;                 // Generator
  Int   order;             // Curve order

private:

  uint8_t GetByte(std::string &str, int idx);

  Int GetY(Int x, bool isEven);
  Point GTable[256*32];       // Generator table

};

#endif // SECP256K1H
