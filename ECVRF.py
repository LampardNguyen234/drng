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
        pi = {'gamma': gamma, 'c': c,  's': s}
        beta = SHA256.new(EC2OSP(gamma)).hexdigest()

        return {'y': beta, 'pi': pi}
    