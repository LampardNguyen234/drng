from ecdsa.ecdsa import *
from common import *
from Crypto.Random import random

class ECVRF(object):
    def __init__(self, Private_key=None):
        if Private_key != None:
            self.x = Private_key.d
            self.y = Private_key.public_key.point
        else:
            self.x = random.randint(1, ORDER)
            self.y = self.x * G
    
    def Prove(self, alpha):
        H = ECVRF_hash_to_curve(self.y, alpha)
        gamma = H*self.x
        k = random.randint(0, ORDER)
        c = ECVRF_hash_points(G,H,self.y,gamma, k*G, k*H)
        s = (k - c*self.x)% ORDER
        pi = (EC2OSP(gamma), I2OSP(c, 16),  I2OSP(s, 32))

def ECVRF_hash_to_curve(y, alpha):
    return G

def ECVRF_hash_points(g, h, y, gamma, gk, hk):
    return G

def I2OSP(x, xLen):
        if x >= 256^xLen:
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

def EC2OSP(x):
    pass


def OS2ECP():
    pass
