import secp256k1
import time
import multiprocessing as mp
import random
import os

def lcg(seed, mod):
    m = mod
    a = 1025
    c = 3
    current_seed = (seed * a + c) % m
    return current_seed


def process_range(procId, start, width, TARGET_HASH160, seed, queue):
    print(f'Process-{procId} start_seed = {seed}')
    for i in range(width):
        seed = lcg(seed, width)
        pk = start + seed
        P = secp256k1.scalar_multiplication(pk)
        hash160 = secp256k1.publickey_to_hash160(0, True, P)
        if hash160 == TARGET_HASH160:
            print()
            print(f'Found by Process-{procId}')
            queue.put_nowait(pk)
            return
    queue.put_nowait(0)
    
def run_processes(start, TARGET_HASH160, queue):
    cores = mp.cpu_count()
    width = start // cores
    start_points = []
    for i in range(cores):
        start_points.append(start)
        start += width
    processes = []
    for i in range(cores):
        seed = random.randrange(1, width)
        p = mp.Process(target=process_range, args=(i, start_points[i], width, TARGET_HASH160, seed, queue))
        processes.append(p)
        p.start()
    data = queue.get()
    print(f'Privatekey : {data}')
    f = open("found_key.txt", "a")
    f.write(f"{data}\n")
    f.close()
    active = mp.active_children()
    for child in active:
        child.kill()

#==============================================================================
if __name__ == '__main__':
    
    TARGET_HASH160 = '1306b9e4ff56513a476841bac7ba48d69516b1da'
    print(f'Puzzle hash: {TARGET_HASH160}')
    puzzle_bits = 28
    print(f'Puzzle bits: {puzzle_bits} bits')
    LOWER_BOUND = 2**(puzzle_bits-1)   #range_start
    UPPER_BOUND = 2**puzzle_bits  #range_end
    print(f'Scan Range : {LOWER_BOUND} -> {UPPER_BOUND}')
    print()
    queue = mp.Queue()
    start_time = time.time()
    
    run_processes(LOWER_BOUND, TARGET_HASH160, queue)
    
    elapsed_time = time.time() - start_time
    hours, rem = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(rem, 60)
    print(f'Time taken: {int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds')    
