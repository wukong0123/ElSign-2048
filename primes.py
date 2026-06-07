import math
import secrets
import random

def generate_sieve(limit: int) -> list[int]:
    sieve = [True] * (limit + 1)
    for p in range(2, int(limit**0.5) + 1):
        if sieve[p]:
            for i in range(p * p, limit + 1, p):
                sieve[i] = False
    return [p for p in range(2, limit + 1) if sieve[p]]

# Generate dynamic sieve up to 65536
SMALL_PRIMES = generate_sieve(65536)

def jacobi(a: int, n: int) -> int:
    a %= n
    t = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            r = n % 8
            if r == 3 or r == 5:
                t = -t
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            t = -t
        a %= n
    if n == 1:
        return t
    return 0

def lucas_probable_prime(n: int, D: int, P: int, Q: int) -> bool:
    d = n + 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
        
    def u_v(k):
        U, V = 1, P
        Qk = Q
        b = bin(k)[3:]
        for bit in b:
            U_2k = (U * V) % n
            V_2k = (V * V - 2 * Qk) % n
            Qk = (Qk * Qk) % n
            if bit == '0':
                U, V = U_2k, V_2k
            else:
                U_next = (P * U_2k + V_2k)
                if U_next % 2 != 0: U_next += n
                U_next //= 2
                V_next = (D * U_2k + P * V_2k)
                if V_next % 2 != 0: V_next += n
                V_next //= 2
                U, V = U_next % n, V_next % n
                Qk = (Qk * Q) % n
        return U, V
        
    U, V = u_v(d)
    if U == 0 or V == 0:
        return True
    Qd = pow(Q, d, n)
    for _ in range(s - 1):
        V = (V * V - 2 * Qd) % n
        Qd = (Qd * Qd) % n
        if V == 0:
            return True
    return False

def is_probable_prime(n: int, k: int = 40) -> bool:
    """Baillie-PSW primality test."""
    if n <= 1: return False
    if n == 2: return True
    if n % 2 == 0: return False
    
    # 1. Trial division with dynamic sieve
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
            
    # 2. Base-2 Miller-Rabin
    d = n - 1
    r = 0
    while d % 2 == 0:
        r += 1
        d //= 2
    x = pow(2, d, n)
    if x != 1 and x != n - 1:
        is_comp = True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                is_comp = False
                break
        if is_comp:
            return False
            
    # 3. Check if n is a perfect square (prevents infinite loop in finding D)
    s = math.isqrt(n)
    if s * s == n:
        return False
        
    # 4. Find D for Lucas
    D = 5
    while True:
        gcd = math.gcd(abs(D), n)
        if 1 < gcd < n:
            return False
        if jacobi(D, n) == -1:
            break
        if D > 0: D = -D - 2
        else: D = -D + 2
        
    P = 1
    Q = (1 - D) // 4
    
    # 4. Strong Lucas Probable Prime Test
    return lucas_probable_prime(n, D, P, Q)

def generate_probable_prime(bits: int) -> int:
    while True:
        p = secrets.randbits(bits)
        # Ensure it has exactly 'bits' length and is odd
        p |= (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p

def generate_provable_prime(bits: int):
    """
    Generate a provable prime using a simplified Pocklington theorem.
    It builds a prime p = 2 * R * q + 1, where q is a provable prime > sqrt(p).
    Returns (p, certificate_dict).
    """
    if bits <= 32:
        while True:
            p = generate_probable_prime(bits)
            if p > 2:
                return p, {"type": "Base", "p": p}
                
    # We need q > sqrt(p). So q must have at least bits/2 + 1 bits.
    # To be safe and ensure p has exactly `bits` bits, we pick q_bits = bits // 2 + 2
    q_bits = bits // 2 + 2
    q, q_cert = generate_provable_prime(q_bits)
    
    # We want p = 2 * R * q + 1 to have `bits` bits.
    # 2^(bits-1) <= 2 * R * q + 1 < 2^bits
    # R approximately needs (bits - q_bits - 1) bits.
    r_bits = bits - q_bits - 1
    if r_bits < 1:
        r_bits = 1
        
    while True:
        R = secrets.randbits(r_bits) | 1 # R must be odd so p is not divisible by something trivial
        # Ensure R has enough bits so p reaches `bits` length
        R |= (1 << (r_bits - 1))
        
        p = 2 * R * q + 1
        
        if p.bit_length() != bits:
            continue
            
        if not is_probable_prime(p, 5): # Quick check
            continue
            
        # Pocklington test
        # We need an 'a' such that a^(p-1) == 1 mod p, and gcd(a^((p-1)/q) - 1, p) == 1
        a = 2
        while a < 200:
            if pow(a, p - 1, p) == 1:
                if math.gcd(pow(a, (p - 1) // q, p) - 1, p) == 1:
                    cert = {
                        "type": "Pocklington",
                        "p": p,
                        "a": a,
                        "R": R,
                        "q": q_cert
                    }
                    return p, cert
            a += 1

def verify_prime_certificate(cert: dict) -> bool:
    """
    Verify a prime certificate.
    """
    if cert["type"] == "Base":
        p = cert["p"]
        # In a real rigorous setup we might trial-divide, but here we just check if it's small and prime
        if p > 2**40:
            return False # Base case too large
        return is_probable_prime(p, 40)
        
    elif cert["type"] == "Pocklington":
        p = cert["p"]
        a = cert["a"]
        R = cert["R"]
        q_cert = cert["q"]
        q = q_cert["p"]
        
        if p != 2 * R * q + 1:
            return False
            
        if q <= math.isqrt(p):
            return False
            
        if pow(a, p - 1, p) != 1:
            return False
            
        if math.gcd(pow(a, (p - 1) // q, p) - 1, p) != 1:
            return False
            
        return verify_prime_certificate(q_cert)
        
    return False
