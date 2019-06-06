"""Common models and utility functions
"""

from Crypto.Hash import SHA256
from ecdsa.ecdsa import curve_256, generator_256, Signature, Public_key
from ecdsa.ellipticcurve import Point
from Crypto.Random import random

CURVE = curve_256
G = generator_256
ORDER = G.order()

def ECVRF_hash_to_curve(alpha, Y=None):
    """Hash an integer in to the target curve
    
    Arguments:\n
        Y -- An additional input point on the elliptic curve (usually the public key)
        alpha -- An input integer
    
    Returns: alpha * Generator + Y
    """
    if Y is None:
        return alpha * G
    else:
        return alpha*G + Y

def ECVRF_hash_points(g, h, pk, gamma, gk, hk):
    """Calculate the hash of many points, used in the VRF
    
    Arguments:\n
        g, h, pk, gamma, gk, hk -- Points on curve
    """
    ha = SHA256.new()
    ha.update(str(g).encode())
    ha.update(str(h).encode())
    ha.update(str(pk).encode())
    ha.update(str(gamma).encode())
    ha.update(str(gk).encode())
    ha.update(str(hk).encode())

    return int(ha.hexdigest(), 16) % ORDER


def compute_threshold(k, n, l):
    """Computes the threshold for a round given k, n, l
    
    Arguments:\n
        k -- the expected number of contributors
        n -- the total number of parties
        l -- the length of the output of the VRF (in bits)
    """    
    return k*(2**l)//(n+1)

def verify_ZKP(Y, M, C, D, c, z):
    """Verifies that M has been decrypted from the ciphertext (C,D)
    
    Arguments:\n
        Y -- the public key
        M -- the decrypted point
        (C, D) -- the ciphertext
        (c, z) -- the proof of proper decryption 
    """
    B0 = z*G + (ORDER - c)*Y
    D2 = D + (ORDER - 1)*M
    B1 = z*C + (ORDER - c)*D2

    h = SHA256.new()
    h.update(str(Y).encode())
    h.update(str(C).encode())
    h.update(str(D2).encode())
    h.update(str(B0).encode())
    h.update(str(B1).encode())

    return c == int(h.hexdigest(), 16)

def generate_ticket(pubkey, nonce):
    """Generates a new ticket for a round
    
    Arguments:\n
        pubkey -- the public key of the Requester
        nonce -- a random number
    """    

    h = SHA256.new()
    h.update(str(pubkey).encode())
    h.update(str(nonce).encode())
    return int(h.hexdigest(), 16)

def hash(M):
    """Computes the hash of a point on the curve

    Arguments:\n
        M -- point to be hashed
    """
    h = SHA256.new()
    h.update(str(M).encode())
    return int(h.hexdigest(), 16)

def random_order():
    """Generates a random number between 0 and the order of the elliptic curve
    """
    return random.randint(0, ORDER)

def create_pubkey_from_point(P):
    """Creates an ECDSA public key from the given point
    
    Arguments:\n
        P -- the point of the public key
    """
    return Public_key(G, P)

def parse_point(json_point):
    """Extracts an elliptic curve point from the given JSON
    
    Arguments:\n
        json_point -- JSON representation of the point
    """

    return Point.from_dictionary(CURVE, json_point)

def parse_signature(json_sigma):
    """Extracts an ECDSA signature from the given JSON
    
    Arguments:\n
        json_sigma -- JSON representation of the signature
    """
    return Signature.from_dictionary(json_sigma)

def egcd(a, b):
    """Computes the Greatest Common Divisor of two numbers
    
    Arguments:\n
        a, b -- the input numbers
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """Computes the modular inverse of a in modulo m
    
    Arguments:\n
        a -- the input
        m -- the modulo
    
    Raises:\n
        Exception: if a does not have a modular inverse in modulo m
    
    Returns:\n
        a^-1 -- the modulo inverse of a in modulo m
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m