import secp256k1

pk = 227634408
print(secp256k1.privatekey_to_hash160(0, True, pk))
