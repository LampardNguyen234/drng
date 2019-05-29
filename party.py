from common import *
from ecdsa.ecdsa import Private_key, Public_key
from ECVRF import ECVRF
from Crypto.Random import random
from Crypto.Hash import SHA256

class Party(object):
    def __init__(self, private_key = None):
        if private_key is None:
            d = RandomOrder()
            point = d*G
            self.public_key = Public_key(G, point)
            self.private_key = Private_key(self.public_key, d)
        else:
            self.private_key = private_key
            self.public_key = self.private_key.public_key
        
        self.VRF = ECVRF(self.private_key)

    def CheckEligibility(self, T, Th):
        out = self.VRF.Prove(T)
        beta = out['beta']
        pi = out['pi']
        if beta < Th:
            return True, beta, pi
        else:
            return False, None, None

    def Contribute(self, T):
        eligi, beta, pi = self.CheckEligibility(T, Th)
        if eligi:
            Y = get_public_key_from_requester()
            x = RandomOrder()
            M = x*G

            k = RandomOrder()

            C = k*G
            D = k*Y + M

            h = SHA256.new()
            h.update(str(C).encode())
            h.update(str(D).encode())
            h = h.hexdigest()
            h = int(h, 16)

            sigma = self.private_key.sign(h, RandomOrder())

            return PoC(self.public_key, T, C, D, sigma)

    def CheckEligibility(self, T, Th):
        pass