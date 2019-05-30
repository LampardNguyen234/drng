"""
Common models and utility functions
"""
from Crypto.Hash import SHA256
from ecdsa.ecdsa import curve_256, generator_256, Signature, Public_key
from ecdsa.ellipticcurve import Point
from Crypto.Random import random

CURVE = curve_256
G = generator_256
ORDER = G.order()

def ECVRF_hash_to_curve(alpha, pk=None):
    """Hash an integer in to the target curve
    
    Arguments:
        y  -- An additional input (usually the public key)
        alpha [Int] -- An input integer
    
    Returns:
        alpha * Generator + Y
    """
    if pk is None:
        return alpha * G
    else:
        return alpha*G + pk

def ECVRF_hash_points(g, h, pk, gamma, gk, hk):
    """Calculate the hash of many points, used in the VRF
    
    Arguments:
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

def create_point_from_XY(Px, Py):
    return Point(CURVE, Px, Py)

def compute_threshold(k, n, l):    
    return k*(2**l)//(n+1)

def verify_ZKP(Y, M, C, D, c, z):
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

def generate_ticket(publicKey, nonce):
    h = SHA256.new()
    h.update(str(publicKey).encode())
    h.update(str(nonce).encode())
    return int(h.hexdigest(), 16)

def EC_point_from_JSON(JSON_point):
    """Extracts an elliptic curve point from the given JSON
    
    Arguments:
        JSON_point -- JSON representation of the point
    """
    Px = JSON_point['x']
    Py = JSON_point['y']
    return create_point_from_XY(Px, Py)

def random_order():
    return random.randint(0, ORDER)

def create_signature_from_rs(r, s):
    return Signature(r,s)

def create_pubkey_from_point(P):
    return Public_key(G, P)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m