#include "SECP256k1.h"
#include "../hash/sha256.h"
#include "../hash/ripemd160.h"
#include "../base58/Base58.h"
#include "../bech32/Bech32.h"
#include <string.h>

Secp256K1::Secp256K1() {
}

void Secp256K1::Init() {

  // Prime for the finite field
  Int P;
  P.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

  // Set up field
  Int::SetupField(&P);

  // Generator point and order
  G.x.SetBase16("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
  G.y.SetBase16("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
  G.z.SetInt32(1);
  order.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

  Int::InitK1(&order);

  // Compute Generator table
  Point N(G);
  for(int i = 0; i < 32; i++) {
    GTable[i * 256] = N;
    N = DoubleDirect(N);
    for (int j = 1; j < 255; j++) {
      GTable[i * 256 + j] = N;
      N = AddDirect(N, GTable[i * 256]);
    }
    GTable[i * 256 + 255] = N; // Dummy point for check function
  }

}

Secp256K1::~Secp256K1() {
}

void PrintResult(bool ok) {
  if(ok) {
    printf("OK\n");
  }
  else {
    printf("Failed !\n");
  }
}

Point Secp256K1::ComputePublicKey(Int *privKey) {

  int i = 0;
  uint8_t b;
  Point Q;
  Q.Clear();

  // Search first significant byte
  for (i = 0; i < 32; i++) {
    b = privKey->GetByte(i);
    if(b)
      break;
  }
  Q = GTable[256 * i + (b-1)];
  i++;

  for(; i < 32; i++) {
    b = privKey->GetByte(i);
    if(b)
      Q = Add2(Q, GTable[256 * i + (b-1)]);
  }

  Q.Reduce();
  return Q;

}

Point Secp256K1::NextKey(Point &key) {
  // Input key must be reduced and different from G
  // in order to use AddDirect
  return AddDirect(key,G);
}

Int Secp256K1::DecodePrivateKey(char *key, bool *compressed) {

  Int ret;
  ret.SetInt32(0);
  std::vector<unsigned char> privKey;

  if(key[0] == '5') {

    // Not compressed
    DecodeBase58(key, privKey);
    if(privKey.size() != 37) {
      printf("Invalid private key, size != 37 (size=%d)!\n",(int)privKey.size());
      ret.SetInt32(-1);
      return ret;
    }

    if(privKey[0] != 0x80) {
      printf("Invalid private key, wrong prefix !\n");
      return ret;
    }

    int count = 31;
    for(int i = 1; i < 33; i++)
      ret.SetByte(count--,privKey[i]);

    // Compute checksum
    unsigned char c[4];
    sha256_checksum(privKey.data(), 33, c);

    if( c[0]!=privKey[33] || c[1]!=privKey[34] ||
        c[2]!=privKey[35] || c[3]!=privKey[36] ) {
      printf("Warning, Invalid private key checksum !\n");
    }

    *compressed = false;
    return ret;

  } else if(key[0] == 'K' || key[0] == 'L') {

    // Compressed
    DecodeBase58(key,privKey);
    if(privKey.size() != 38) {
      printf("Invalid private key, size != 38 (size=%d)!\n",(int)privKey.size());
      ret.SetInt32(-1);
      return ret;
    }

    int count = 31;
    for(int i = 1; i < 33; i++)
      ret.SetByte(count--,privKey[i]);

    // Compute checksum
    unsigned char c[4];
    sha256_checksum(privKey.data(), 34, c);

    if( c[0]!=privKey[34] || c[1]!=privKey[35] ||
        c[2]!=privKey[36] || c[3]!=privKey[37] ) {
      printf("Warning, Invalid private key checksum !\n");
    }

    *compressed = true;
    return ret;

  }

  printf("Invalid private key, not starting with 5,K or L !\n");
  ret.SetInt32(-1);
  return ret;

}

Int Secp256K1::DecodePrivateKey2(char *key) {

  Int ret;
  ret.SetInt32(0);
  std::vector<unsigned char> privKey;

  if(key[0] == '5') {

    // Not compressed
    DecodeBase58(key,privKey);
    if(privKey.size() != 37) {
      printf("Invalid private key, size != 37 (size=%d)!\n",(int)privKey.size());
      ret.SetInt32(-1);
      return ret;
    }

    if(privKey[0] != 0x80) {
      printf("Invalid private key, wrong prefix !\n");
      return ret;
    }

    int count = 31;
    for(int i = 1; i < 33; i++)
      ret.SetByte(count--,privKey[i]);

    // Compute checksum
    unsigned char c[4];
    sha256_checksum(privKey.data(), 33, c);

    if( c[0]!=privKey[33] || c[1]!=privKey[34] ||
        c[2]!=privKey[35] || c[3]!=privKey[36] ) {
      printf("Warning, Invalid private key checksum !\n");
    }

    return ret;

  } else if(key[0] == 'K' || key[0] == 'L') {

    // Compressed
    DecodeBase58(key, privKey);
    if(privKey.size() != 38) {
      printf("Invalid private key, size != 38 (size=%d)!\n",(int)privKey.size());
      ret.SetInt32(-1);
      return ret;
    }

    int count = 31;
    for(int i = 1; i < 33; i++)
      ret.SetByte(count--,privKey[i]);

    // Compute checksum
    unsigned char c[4];
    sha256_checksum(privKey.data(), 34, c);

    if( c[0]!=privKey[34] || c[1]!=privKey[35] ||
        c[2]!=privKey[36] || c[3]!=privKey[37] ) {
      printf("Warning, Invalid private key checksum !\n");
    }

    return ret;

  }

  printf("Invalid private key, not starting with 5,K or L !\n");
  ret.SetInt32(-1);
  return ret;

}

std::string Secp256K1::GetHashFromP2PKHAddress(char* address) {
  std::vector<unsigned char> hash160;
  DecodeBase58(address, hash160);
  std::string ret(hash160.begin(), hash160.end());
  return ret;
}

uint8_t Secp256K1::GetByte(std::string &str, int idx) {

  char tmp[3];
  int  val;

  tmp[0] = str.data()[2 * idx];
  tmp[1] = str.data()[2 * idx + 1];
  tmp[2] = 0;

  if (sscanf(tmp, "%X", &val) != 1) {
    printf("ParsePublicKeyHex: Error invalid public key specified (unexpected hexadecimal digit)\n");
    exit(-1);
  }

  return (uint8_t)val;

}

Point Secp256K1::ParsePublicKeyHex(std::string str, bool &isCompressed) {

  Point ret;
  ret.Clear();

  if (str.length() < 2) {
    printf("ParsePublicKeyHex: Error invalid public key specified (66 or 130 character length)\n");
    exit(-1);
  }

  uint8_t type = GetByte(str, 0);

  switch (type) {

    case 0x02:
      if (str.length() != 66) {
        printf("ParsePublicKeyHex: Error invalid public key specified (66 character length)\n");
        exit(-1);
      }
      for (int i = 0; i < 32; i++)
        ret.x.SetByte(31 - i, GetByte(str, i + 1));
      ret.y = GetY(ret.x, true);
      isCompressed = true;
      break;

    case 0x03:
      if (str.length() != 66) {
        printf("ParsePublicKeyHex: Error invalid public key specified (66 character length)\n");
        exit(-1);
      }
      for (int i = 0; i < 32; i++)
        ret.x.SetByte(31 - i, GetByte(str, i + 1));
      ret.y = GetY(ret.x, false);
      isCompressed = true;
      break;

    case 0x04:
      if (str.length() != 130) {
        printf("ParsePublicKeyHex: Error invalid public key specified (130 character length)\n");
        exit(-1);
      }
      for (int i = 0; i < 32; i++)
        ret.x.SetByte(31 - i, GetByte(str, i + 1));
      for (int i = 0; i < 32; i++)
        ret.y.SetByte(31 - i, GetByte(str, i + 33));
      isCompressed = false;
      break;

    default:
      printf("ParsePublicKeyHex: Error invalid public key specified (Unexpected prefix (only 02,03 or 04 allowed)\n");
      exit(-1);
  }

  ret.z.SetInt32(1);

  if (!EC(ret)) {
    printf("ParsePublicKeyHex: Error invalid public key specified (Not lie on elliptic curve)\n");
    exit(-1);
  }

  return ret;

}

Point Secp256K1::ParsePublicKeyHex2(char* pubkey) {

  Point ret;
  ret.Clear();

  std::string str(pubkey);

  if (str.length() < 2) {
    printf("ParsePublicKeyHex: Error invalid public key specified (66 or 130 character length)\n");
    exit(-1);
  }

  uint8_t type = GetByte(str, 0);

  switch (type) {

    case 0x02:
      if (str.length() != 66) {
        printf("ParsePublicKeyHex: Error invalid public key specified (66 character length)\n");
        exit(-1);
      }
      for (int i = 0; i < 32; i++)
        ret.x.SetByte(31 - i, GetByte(str, i + 1));
      ret.y = GetY(ret.x, true);
      break;

    case 0x03:
      if (str.length() != 66) {
        printf("ParsePublicKeyHex: Error invalid public key specified (66 character length)\n");
        exit(-1);
      }
      for (int i = 0; i < 32; i++)
        ret.x.SetByte(31 - i, GetByte(str, i + 1));
      ret.y = GetY(ret.x, false);
      break;

    case 0x04:
      if (str.length() != 130) {
        printf("ParsePublicKeyHex: Error invalid public key specified (130 character length)\n");
        exit(-1);
      }
      for (int i = 0; i < 32; i++)
        ret.x.SetByte(31 - i, GetByte(str, i + 1));
      for (int i = 0; i < 32; i++)
        ret.y.SetByte(31 - i, GetByte(str, i + 33));
      break;

    default:
      printf("ParsePublicKeyHex: Error invalid public key specified (Unexpected prefix (only 02,03 or 04 allowed)\n");
      exit(-1);
  }

  ret.z.SetInt32(1);

  if (!EC(ret)) {
    printf("ParsePublicKeyHex: Error invalid public key specified (Not lie on elliptic curve)\n");
    exit(-1);
  }

  return ret;

}

void Secp256K1::GetPubKeyBytes(bool compressed, Point& pubKey, unsigned char* publicKeyBytes)
{
  if (!compressed) {

    // Full public key
    publicKeyBytes[0] = 0x4;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
    pubKey.y.Get32Bytes(publicKeyBytes + 33);
  }
  else {

    // Compressed public key
    publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);


    //for (int i = 0; i < 33; i++) {
    //  printf("%02x", ((uint8_t*)publicKeyBytes)[i]);
    //}
    //printf("\n");
  }
}

Point Secp256K1::SetPubKeyBytes(unsigned char* publicKeyBytesIn)
{
    Point ret;
    //ret.z.SetInt32(1);
    ret.x.Set32Bytes(publicKeyBytesIn + 1);
    ret.y.Set32Bytes(publicKeyBytesIn + 33);
    return ret;
}

void Secp256K1::GetXBytes(bool compressed, Point& pubKey, unsigned char* publicKeyBytes)
{
  if (!compressed) {

    // Full public key
    //publicKeyBytes[0] = 0x4;
    pubKey.x.Get32Bytes(publicKeyBytes);
    pubKey.y.Get32Bytes(publicKeyBytes + 32);
  }
  else {

    // Compressed public key
    //publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes(publicKeyBytes);


    //for (int i = 0; i < 33; i++) {
    //  printf("%02x", ((uint8_t*)publicKeyBytes)[i]);
    //}
    //printf("\n");
  }
}

std::string Secp256K1::GetPublicKeyHex(bool compressed, Point &pubKey) {

  unsigned char publicKeyBytes[128];
  char tmp[3];
  std::string ret;

  if (!compressed) {

    // Full public key
    publicKeyBytes[0] = 0x4;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
    pubKey.y.Get32Bytes(publicKeyBytes + 33);

    for (int i = 0; i < 65; i++) {
      //sprintf(tmp, "%02X", (int)publicKeyBytes[i]); //uppercase
      sprintf(tmp, "%02x", (int)publicKeyBytes[i]); //lowercase
      ret.append(tmp);
    }

  } else {

    // Compressed public key
    publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);

    for (int i = 0; i < 33; i++) {
      //sprintf(tmp, "%02X", (int)publicKeyBytes[i]); //uppercase
      sprintf(tmp, "%02x", (int)publicKeyBytes[i]); //lowercase
      ret.append(tmp);
    }

  }

  return ret;

}

void Secp256K1::GetHash160(int type, bool compressed, Point &pubKey, unsigned char *hash) {

  unsigned char shapk[64];

  switch (type) {

  case P2PKH:
  case BECH32:
  {
    unsigned char publicKeyBytes[128];

    if (!compressed) {

      // Full public key
      publicKeyBytes[0] = 0x4;
      pubKey.x.Get32Bytes(publicKeyBytes + 1);
      pubKey.y.Get32Bytes(publicKeyBytes + 33);
      sha256_65(publicKeyBytes, shapk);

    } else {

      // Compressed public key
      publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
      pubKey.x.Get32Bytes(publicKeyBytes + 1);
      sha256_33(publicKeyBytes, shapk);

    }

    ripemd160_32(shapk, hash);
  }
  break;

  case P2SH:
  {

    // Redeem Script (1 to 1 P2SH)
    unsigned char script[64];

    script[0] = 0x00;  // OP_0
    script[1] = 0x14;  // PUSH 20 bytes
    GetHash160(P2PKH, compressed, pubKey, script + 2);

    sha256(script, 22, shapk);
    ripemd160_32(shapk, hash);

  }
  break;

  }

}

std::string Secp256K1::GetPrivAddress(bool compressed, Int &privKey) {

  unsigned char address[38];

  address[0] = 0x80; // Mainnet
  privKey.Get32Bytes(address + 1);

  if( compressed ) {

    // compressed suffix
    address[33] = 1;
    sha256_checksum(address, 34, address + 34);
    return EncodeBase58(address, address + 38);

  } else {

    // Compute checksum
    sha256_checksum(address, 33, address + 33);
    return EncodeBase58(address, address + 37);

  }

}

std::string Secp256K1::GetAddressFromHash(int type, bool compressed, unsigned char *hash160) {

  unsigned char address[25];
  switch(type) {

    case P2PKH:
      address[0] = 0x00;
      break;

    case P2SH:
      address[0] = 0x05;
      break;

    case BECH32:
    {
      char output[128];
      segwit_addr_encode(output, "bc", 0, hash160, 20);
      return std::string(output);
    }
    break;
  }
  memcpy(address + 1, hash160, 20);
  sha256_checksum(address,21,address+21);

  // Base58
  return EncodeBase58(address, address + 25);

}

std::string Secp256K1::GetAddressFromPub(int type, bool compressed, Point &pubKey) {

  unsigned char address[25];

  switch (type) {

  case P2PKH:
    address[0] = 0x00;
    break;

  case P2SH:
    if (!compressed) {
      return " P2SH: Only compressed key ";
    }
    address[0] = 0x05;
    break;
  }

  GetHash160(type, compressed, pubKey, address + 1);
  sha256_checksum(address, 21, address + 21);

  // Base58
  return EncodeBase58(address, address + 25);

}

std::string Secp256K1::GetBech32Address(Point &pubKey) {

   char output[128];
   uint8_t h160[20];
   GetHash160(BECH32, true, pubKey, h160);
   segwit_addr_encode(output, "bc", 0, h160, 20);
   return std::string(output);

}

std::string Secp256K1::GetBech32P2WSHAddress(Point &pubKey) {

   unsigned char p2wsh[35];
   p2wsh[0]  = 0x21;
   p2wsh[1]  = pubKey.y.IsEven() ? 0x2 : 0x3;
   pubKey.x.Get32Bytes(p2wsh + 2);
   p2wsh[34] = 0xac;

   unsigned char sha256pk[64];
   sha256(p2wsh, 35, sha256pk);

   char p2wsh_address[62];
   segwit_addr_encode(p2wsh_address, "bc", 0, sha256pk, 32);

   return std::string(p2wsh_address);

}

bool Secp256K1::CheckPudAddress(std::string address) {

  std::vector<unsigned char> pubKey;
  DecodeBase58(address,pubKey);

  if(pubKey.size()!=25)
    return false;

  // Check checksum
  unsigned char chk[4];
  sha256_checksum(pubKey.data(), 21, chk);

  return  (pubKey[21] == chk[0]) &&
          (pubKey[22] == chk[1]) &&
          (pubKey[23] == chk[2]) &&
          (pubKey[24] == chk[3]);

}

Point Secp256K1::PointMultiplication(Point &P, Int *scalar) {
  Point R, T;
  int  no_of_bits, loop;
  no_of_bits = scalar->GetBitLength();
  R.Set(P); R.z.SetInt32(1);
  T.Set(P); T.z.SetInt32(1);
  for(loop = no_of_bits - 2; loop >= 0; loop--) {
      R = Double(R);
      if(scalar->GetBit(loop)) { R = Add2(R, T); }        
  }
  R.Reduce();
  return R;
}

Point Secp256K1::AddDirect(Point &p1, Point &p2) {

  Int _s;
  Int _p;
  Int dy;
  Int dx;
  Point r;
  r.z.SetInt32(1);

  dy.ModSub(&p2.y, &p1.y);
  dx.ModSub(&p2.x, &p1.x);
  dx.ModInv();
  _s.ModMulK1(&dy, &dx);     // s = (p2.y-p1.y)*inverse(p2.x-p1.x);

  _p.ModSquareK1(&_s);       // _p = pow2(s)

  r.x.ModSub(&_p, &p1.x);
  r.x.ModSub(&p2.x);       // rx = pow2(s) - p1.x - p2.x;

  r.y.ModSub(&p2.x, &r.x);
  r.y.ModMulK1(&_s);
  r.y.ModSub(&p2.y);       // ry = - p2.y - s*(ret.x-p2.x);

  return r;

}

Point Secp256K1::AddPoints(Point &p1, Point &p2) {

  Int _s, dx, dy;
  Point r;
  r.z.SetInt32(1);

  dy.ModSub(&p2.y, &p1.y);
  dx.ModSub(&p2.x, &p1.x);
  dx.ModInv();
  _s.ModMulK1(&dy, &dx);     // s = (p2.y-p1.y)*inverse(p2.x-p1.x);

  r.x.ModSquareK1(&_s);       // _p = pow2(s)
  r.x.ModSub(&p1.x);
  r.x.ModSub(&p2.x);       // rx = pow2(s) - p1.x - p2.x;

  r.y.ModSub(&p2.x, &r.x);
  r.y.ModMulK1(&_s);
  r.y.ModSub(&p2.y);       // ry = - p2.y - s*(ret.x-p2.x);

  return r;

}

Point Secp256K1::AddPoints2(Point &p1, Point &p2) {

  Int _s, dx, dy;
  Point r;
  r.z.SetInt32(1);
  Int _ZERO((uint64_t)0);

  if (p1.equals2(p2)) {
    r = DoubleDirect(p1);
    return r;
  }
  
  if (p1.x.IsEqual(&p2.x)) {
      r.x.SetInt32(0);
      r.y.SetInt32(0);
      return r;
  }
  
  if (p1.x.IsEqual(&_ZERO)) {
      r.x.Set(&p2.x);
      r.y.Set(&p2.y);
      return r;
  }
  
  if (p2.x.IsEqual(&_ZERO)) {
      r.x.Set(&p1.x);
      r.y.Set(&p1.y);
      return r;
  }


  dy.ModSub(&p2.y, &p1.y);
  dx.ModSub(&p2.x, &p1.x);
  dx.ModInv();
  _s.ModMulK1(&dy, &dx);     // s = (p2.y-p1.y)*inverse(p2.x-p1.x);

  r.x.ModSquareK1(&_s);       // _p = pow2(s)
  r.x.ModSub(&p1.x);
  r.x.ModSub(&p2.x);       // rx = pow2(s) - p1.x - p2.x;

  r.y.ModSub(&p2.x, &r.x);
  r.y.ModMulK1(&_s);
  r.y.ModSub(&p2.y);       // ry = - p2.y - s*(ret.x-p2.x);

  return r;

}

Point Secp256K1::SubtractPoints(Point &p1, Point &p2) {
  Point Q1, Q2;
  Q1.Set(p2);
  Q1.y.ModNeg();
  Q1.z.SetInt32(1);
  Q2 = AddPoints(p1, Q1);
  return Q2;
}

Point Secp256K1::SubtractPoints2(Point &p1, Point &p2) {
  Point Q1, Q2;
  Q1.Set(p2);
  Q1.y.ModNeg();
  Q1.z.SetInt32(1);
  Q2 = AddPoints2(p1, Q1);
  return Q2;
}

Point Secp256K1::Add2(Point &p1, Point &p2) {

  // P2.z = 1

  Int u;
  Int v;
  Int u1;
  Int v1;
  Int vs2;
  Int vs3;
  Int us2;
  Int a;
  Int us2w;
  Int vs2v2;
  Int vs3u2;
  Int _2vs2v2;
  Point r;

  u1.ModMulK1(&p2.y, &p1.z);
  v1.ModMulK1(&p2.x, &p1.z);
  u.ModSub(&u1, &p1.y);
  v.ModSub(&v1, &p1.x);
  us2.ModSquareK1(&u);
  vs2.ModSquareK1(&v);
  vs3.ModMulK1(&vs2, &v);
  us2w.ModMulK1(&us2, &p1.z);
  vs2v2.ModMulK1(&vs2, &p1.x);
  _2vs2v2.ModAdd(&vs2v2, &vs2v2);
  a.ModSub(&us2w, &vs3);
  a.ModSub(&_2vs2v2);

  r.x.ModMulK1(&v, &a);

  vs3u2.ModMulK1(&vs3, &p1.y);
  r.y.ModSub(&vs2v2, &a);
  r.y.ModMulK1(&r.y, &u);
  r.y.ModSub(&vs3u2);

  r.z.ModMulK1(&vs3, &p1.z);

  return r;

}

Point Secp256K1::Add(Point &p1,Point &p2) {

  Int u;
  Int v;
  Int u1;
  Int u2;
  Int v1;
  Int v2;
  Int vs2;
  Int vs3;
  Int us2;
  Int w;
  Int a;
  Int us2w;
  Int vs2v2;
  Int vs3u2;
  Int _2vs2v2;
  Int x3;
  Int vs3y1;
  Point r;

  /*
  U1 = Y2 * Z1
  U2 = Y1 * Z2
  V1 = X2 * Z1
  V2 = X1 * Z2
  if (V1 == V2)
    if (U1 != U2)
      return POINT_AT_INFINITY
    else
      return POINT_DOUBLE(X1, Y1, Z1)
  U = U1 - U2
  V = V1 - V2
  W = Z1 * Z2
  A = U ^ 2 * W - V ^ 3 - 2 * V ^ 2 * V2
  X3 = V * A
  Y3 = U * (V ^ 2 * V2 - A) - V ^ 3 * U2
  Z3 = V ^ 3 * W
  return (X3, Y3, Z3)
  */

  u1.ModMulK1(&p2.y,&p1.z);
  u2.ModMulK1(&p1.y,&p2.z);
  v1.ModMulK1(&p2.x,&p1.z);
  v2.ModMulK1(&p1.x,&p2.z);
  u.ModSub(&u1,&u2);
  v.ModSub(&v1,&v2);
  w.ModMulK1(&p1.z,&p2.z);
  us2.ModSquareK1(&u);
  vs2.ModSquareK1(&v);
  vs3.ModMulK1(&vs2,&v);
  us2w.ModMulK1(&us2,&w);
  vs2v2.ModMulK1(&vs2,&v2);
  _2vs2v2.ModAdd(&vs2v2,&vs2v2);
  a.ModSub(&us2w,&vs3);
  a.ModSub(&_2vs2v2);

  r.x.ModMulK1(&v,&a);

  vs3u2.ModMulK1(&vs3,&u2);
  r.y.ModSub(&vs2v2,&a);
  r.y.ModMulK1(&r.y,&u);
  r.y.ModSub(&vs3u2);

  r.z.ModMulK1(&vs3,&w);

  return r;
}

Point Secp256K1::DoubleDirect(Point &p) {

  Int _s;
  Int _p;
  Int a;
  Point r;
  r.z.SetInt32(1);

  _s.ModMulK1(&p.x, &p.x);
  _p.ModAdd(&_s, &_s);
  _p.ModAdd(&_s);

  a.ModAdd(&p.y, &p.y);
  a.ModInv();
  _s.ModMulK1(&_p, &a);     // s = (3*pow2(p.x))*inverse(2*p.y);

  _p.ModMulK1(&_s, &_s);
  a.ModAdd(&p.x, &p.x);
  a.ModNeg();
  r.x.ModAdd(&a, &_p);    // rx = pow2(s) + neg(2*p.x);

  a.ModSub(&r.x, &p.x);

  _p.ModMulK1(&a, &_s);
  r.y.ModAdd(&_p, &p.y);
  r.y.ModNeg();           // ry = neg(p.y + s*(ret.x+neg(p.x)));

  return r;
}

Point Secp256K1::Double(Point &p) {


  /*
  if (Y == 0)
    return POINT_AT_INFINITY
    W = a * Z ^ 2 + 3 * X ^ 2
    S = Y * Z
    B = X * Y*S
    H = W ^ 2 - 8 * B
    X' = 2*H*S
    Y' = W*(4*B - H) - 8*Y^2*S^2
    Z' = 8*S^3
    return (X', Y', Z')
  */

  Int z2;
  Int x2;
  Int _3x2;
  Int w;
  Int s;
  Int s2;
  Int b;
  Int _8b;
  Int _8y2s2;
  Int y2;
  Int h;
  Point r;

  z2.ModSquareK1(&p.z);
  z2.SetInt32(0); // a=0
  x2.ModSquareK1(&p.x);
  _3x2.ModAdd(&x2,&x2);
  _3x2.ModAdd(&x2);
  w.ModAdd(&z2,&_3x2);
  s.ModMulK1(&p.y,&p.z);
  b.ModMulK1(&p.y,&s);
  b.ModMulK1(&p.x);
  h.ModSquareK1(&w);
  _8b.ModAdd(&b,&b);
  _8b.ModDouble();
  _8b.ModDouble();
  h.ModSub(&_8b);

  r.x.ModMulK1(&h,&s);
  r.x.ModAdd(&r.x);

  s2.ModSquareK1(&s);
  y2.ModSquareK1(&p.y);
  _8y2s2.ModMulK1(&y2,&s2);
  _8y2s2.ModDouble();
  _8y2s2.ModDouble();
  _8y2s2.ModDouble();

  r.y.ModAdd(&b,&b);
  r.y.ModAdd(&r.y,&r.y);
  r.y.ModSub(&h);
  r.y.ModMulK1(&w);
  r.y.ModSub(&_8y2s2);

  r.z.ModMulK1(&s2,&s);
  r.z.ModDouble();
  r.z.ModDouble();
  r.z.ModDouble();

  return r;
}

Int Secp256K1::GetY(Int x, bool isEven) {

  Int _s;
  Int _p;

  _s.ModSquareK1(&x);
  _p.ModMulK1(&_s,&x);
  _p.ModAdd(7);
  _p.ModSqrt();

  if(!_p.IsEven() && isEven) {
    _p.ModNeg();
  }
  else if(_p.IsEven() && !isEven) {
    _p.ModNeg();
  }

  return _p;

}

Int Secp256K1::GetYToX(Int x, bool isEven) {

  Int _s;
  Int _p;

  _s.ModSquareK1(&x);
  _p.ModMulK1(&_s,&x);
  _p.ModAdd(7);
  _p.ModSqrt();

  if(!_p.IsEven() && isEven) {
    _p.ModNeg();
  }
  else if(_p.IsEven() && !isEven) {
    _p.ModNeg();
  }

  return _p;

}

bool Secp256K1::EC(Point &p) {

  Int _s;
  Int _p;

  _s.ModSquareK1(&p.x);
  _p.ModMulK1(&_s, &p.x);
  _p.ModAdd(7);
  _s.ModMulK1(&p.y, &p.y);
  _s.ModSub(&_p);

  return _s.IsZero(); // ( ((pow2(y) - (pow3(x) + 7)) % P) == 0 );

}
