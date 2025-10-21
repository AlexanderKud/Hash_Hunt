default:
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c secp256k1/Int.cpp -o Int.o
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c secp256k1/Point.cpp -o Point.o
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c secp256k1/SECP256K1.cpp -o SECP256K1.o
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c secp256k1/IntMod.cpp -o IntMod.o
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c secp256k1/Random.cpp -o Random.o
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c secp256k1/IntGroup.cpp -o IntGroup.o
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c base58/Base58.cpp -o Base58.o
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c bech32/Bech32.cpp -o Bech32.o
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c hash/ripemd160.cpp -o ripemd160.o 
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c hash/sha256.cpp -o sha256.o
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c util/util.cpp -o util.o 
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c hash_hunt.cpp -o hash_hunt.o
	g++ -m64 -mssse3 -Wno-write-strings -O1 -c hash_hunt_batch_add.cpp -o hash_hunt_batch_add.o
	g++ -o hash_hunt hash_hunt.o util.o Base58.o Bech32.o SECP256K1.o Int.o IntGroup.o IntMod.o Point.o Random.o ripemd160.o sha256.o
	g++ -o hash_hunt_batch_add hash_hunt_batch_add.o util.o Base58.o Bech32.o SECP256K1.o Int.o IntGroup.o IntMod.o Point.o Random.o ripemd160.o sha256.o
	rm *.o
