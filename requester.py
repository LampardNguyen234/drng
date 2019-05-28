from common import *
from Crypto.Random import random

class Requester(object):
    
    def __init__(self):
        self.x = random.randint(1, ORDER)
        self.Y = self.x * G
        pass

    def decrypt(self, C, D):
        M = D + (ORDER-self.x)*C

        D2 = D + (ORDER - 1)*M

        r = random.randint(1, ORDER)

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

        return (c,z,B0, B1)
