import secp256k1
import time

#puzzle_privkey = 863317
#TARGET_HASH160 = secp256k1.privatekey_to_hash160(0, True, puzzle_privkey)
TARGET_HASH160 = 'fc7385ace07a40ccc214172dde43f81a88ea3bd6'
print(f'Puzzle hash: {TARGET_HASH160}')
puzzle_bits = 25
print(f'Puzzle bits: {puzzle_bits}')
LOWER_BOUND = 2**(puzzle_bits-1)   #range_start
UPPER_BOUND = 2**puzzle_bits  #range_end
print(f'Scan Range : {LOWER_BOUND} -> {UPPER_BOUND}')
pk = LOWER_BOUND
G = secp256k1.scalar_multiplication(1)
slice_count = 5 # number of starting chars to match
hash_slice = TARGET_HASH160[:slice_count]
print(f'Hash slice : {hash_slice} [{slice_count} chars]')
matches = 0

start_time = time.time()

for i in  range(LOWER_BOUND):
    
    P = secp256k1.scalar_multiplication(pk)
    hash160 = secp256k1.publickey_to_hash160(0, True, P)
    if hash160 == TARGET_HASH160:
        print(f'[AWESOME] Found full match: {pk} {hash160}')
        matches += 1
    elif hash160[:slice_count] == hash_slice:
        print(f'Found partial match: {pk} {hash160}')
        matches += 1
    P = secp256k1.add_points(P, G)
    pk += 1

print(f'Total matches: {matches}')
elapsed_time = time.time() - start_time
hours, rem = divmod(elapsed_time, 3600)
minutes, seconds = divmod(rem, 60)
print(f'Time taken: {int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds')    
