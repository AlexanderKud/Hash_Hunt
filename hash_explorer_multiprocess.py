import secp256k1
import time
import multiprocessing as mp


def process_range(processIdx, start, width, TARGET_HASH160, hash_slice, slice_count, matches):
    G = secp256k1.scalar_multiplication(1)
    pk = start
    for i in range(width):
        P = secp256k1.scalar_multiplication(pk)
        hash160 = secp256k1.publickey_to_hash160(0, True, P)
        if hash160 == TARGET_HASH160:
            print(f'[AWESOME] Full match ChildProcess[{processIdx}]: {pk} {hash160}')
            matches.value += 1
        elif hash160[:slice_count] == hash_slice:
            print(f'Hash slice match ChildProcess[{processIdx}]: {pk} {hash160}')
            matches.value += 1
        P = secp256k1.add_points(P, G)
        pk += 1
    
def run_processes(start, TARGET_HASH160, hash_slice, slice_count, matches):
    cores = mp.cpu_count()
    width = start // cores
    start_points = []
    for i in range(cores):
        start_points.append(start)
        start += width
    processes = []
    for i in range(cores):
        p = mp.Process(target=process_range, args=(i, start_points[i], width, TARGET_HASH160, hash_slice, slice_count, matches))
        processes.append(p)
        p.start()
    for p in processes:
        p.join()

#==============================================================================
if __name__ == '__main__':
    
    puzzle_privkey = 2102388551
    TARGET_HASH160 = secp256k1.privatekey_to_hash160(0, True, puzzle_privkey)
    #TARGET_HASH160 = 'adf3bb5409d1684eb9b4a2d8d3d304f030fe80d9'
    print(f'Puzzle hash: {TARGET_HASH160}')
    puzzle_bits = 31
    print(f'Puzzle bits: {puzzle_bits} bits')
    LOWER_BOUND = 2**(puzzle_bits-1)   #range_start
    UPPER_BOUND = 2**puzzle_bits  #range_end
    print(f'Scan Range : {LOWER_BOUND} -> {UPPER_BOUND}')
    slice_count = 7 # number of starting chars to match
    hash_slice = TARGET_HASH160[:slice_count]
    print(f'Hash slice : {hash_slice} [{slice_count} chars]')
    
    matches = mp.Value('i', 0)
    
    start_time = time.time()
    
    run_processes(LOWER_BOUND, TARGET_HASH160, hash_slice, slice_count, matches)
    
    print(f'Total matches: {matches.value}')
    elapsed_time = time.time() - start_time
    hours, rem = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(rem, 60)
    print(f'Time taken: {int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds')    
