import json
import time
import multiprocessing
import os
from primes import generate_provable_prime

def worker(i):
    print(f"[Worker {os.getpid()}] Started generating prime {i+1}/10...", flush=True)
    start_t = time.time()
    p, cert = generate_provable_prime(2048)
    elapsed = time.time() - start_t
    print(f"[Worker {os.getpid()}] Done prime {i+1} in {elapsed:.2f}s", flush=True)
    return {
        "p": p,
        "prime_certificate": cert
    }

def main():
    pool_data = []
    print("Starting parallel generation of 10 provable primes (2048-bit)...")
    start_total = time.time()
    
    num_cores = multiprocessing.cpu_count()
    print(f"Using {num_cores} CPU cores for generation.")
    
    with multiprocessing.Pool(processes=num_cores) as pool:
        results = pool.imap_unordered(worker, range(10))
        for res in results:
            pool_data.append(res)
            # Save intermediate
            with open("certified_pool.json", "w", encoding="utf-8") as f:
                json.dump(pool_data, f, indent=2)
                
    print(f"Completed 10 primes in {time.time() - start_total:.2f}s")

if __name__ == "__main__":
    main()
