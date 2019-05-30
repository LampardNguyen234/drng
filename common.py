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

def I2OSP(x, xLen):
    if x >= 256**xLen:
        raise ValueError("integer too large")
    digits = []

    while x:
        digits.append(int(x % 256))
        x //= 256
    for i in range(xLen - len(digits)):
        digits.append(0)
    return digits[::-1]

def OS2IP(X):
    xLen = len(X)
    X = X[::-1]
    x = 0
    for i in range(xLen):
        x += X[i] * 256^i
    return x

def EC2OSP(P):
    x = P.x()
    y = P.y()
    return I2OSP(x, 32) + I2OSP(y, 32)


def CreatePointFromXY(Px, Py):
    return Point(CURVE, Px, Py)

def ComputeThreshold(k, n, l):    
    return k*(2**l)//(n+1)

def TallyContribute(C, D):
    if len(C) != len(D):
        return None
    C_temp = C[0]
    D_temp = D[0]
    for i in range(1, len(C)):
        C_temp = C_temp + C[i]
        D_temp = D_temp + D[i]
    
    return C_temp, D_temp

def VerifyZKP(Y, M, C, D, c, z):
    B0 = z*G + (ORDER - c)*Y
    D2 = D + (ORDER - 1)*M
    B1 = z*C + (ORDER - c)* D2

    h = SHA256.new()
    h.update(str(Y).encode())
    h.update(str(C).encode())
    h.update(str(D2).encode())
    h.update(str(B0).encode())
    h.update(str(B1).encode())

    return c == int(h.hexdigest(), 16)

def GenerateTicket(publicKey, nonce):
    h = SHA256.new()
    h.update(str(publicKey).encode())
    h.update(str(nonce).encode())
    return int(h.hexdigest(), 16)

def RandomOrder():
    return random.randint(0, ORDER)

def CreateSignatureFromrs(r, s):
    return Signature(r,s)

def CreatePublicKeyFromPoint(P):
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



def get_public_key_from_requester():
    return 10*G

