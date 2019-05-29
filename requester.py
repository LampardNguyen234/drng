from common import *
from Crypto.Random import random

class Requester(object):
    
    def __init__(self, x=None):
        if x is None:
            self.x = RandomOrder()
        else:
            self.x = x
        self.Y = self.x * G
        pass

    def decrypt(self, C, D):
        M = D + (ORDER-self.x)*C

        D2 = D + (ORDER - 1)*M

        r = RandomOrder()

        B0 = r*G
        B1 = r*C

        h = SHA256.new()
        h.update(str(self.Y).encode())
        h.update(str(C).encode())
        h.update(str(D2).encode())
        h.update(str(B0).encode())
        h.update(str(B1).encode())

        c = int(h.hexdigest(), 16)

        z = (r + c*self.x) % ORDER

        return (c,z,B0,B1)
