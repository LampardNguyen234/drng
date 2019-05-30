'''
This module implements an Elliptic Curve-based Verifiable Random Function (ECVRF) based on the instruction from
https://tools.ietf.org/id/draft-goldbe-vrf-01.html
For the sake of being compatible with our protocol in the thesis, sk = x, pk = y
'''
from ecdsa.ecdsa import *
from common import *
from Crypto.Random import random

class ECVRF(object):
    def __init__(self, Private_key=None):
        if Private_key != None:
            self.sk = Private_key.d
            self.pk = Private_key.public_key.point
        else:
            self.sk = random.randint(1, ORDER)
            self.pk = self.sk * G
    
    def Prove(self, alpha):
        """Returns a random number y, a proof pi based on input alpha and the secret key self.sk.
        
        Arguments:
            alpha -- input to the VRF
        """ 
        H = ECVRF_hash_to_curve(alpha, self.pk)
        gamma = H*self.sk
        k = random.randint(0, ORDER)
        c = ECVRF_hash_points(G, H, self.pk, gamma, k*G, k*H)
        s = (k - c*self.sk)% ORDER
        pi = {'gamma': gamma, 'c': c,  's': s}

        h = SHA256.new()
        h.update(str(gamma).encode())
        y = int(h.hexdigest(), 16)

        return {'y': y, 'pi': pi, 'pk': self.pk}
    
    @staticmethod
    def Verify(alpha, pi, pk):
        """Verify the correctness of an output from the Prove function
        
        Arguments:
            alpha -- The input to VRF
            pi -- The proof produced by the Prove function
            pk -- The public key
        """
        #Extract gamma, c, s from pi
        gamma = pi['gamma']
        c = pi['c']
        s = pi['s']

        U = c*pk + s*G
        H = ECVRF_hash_to_curve(alpha, pk)
        V = c*gamma + s*H
        c_prime = ECVRF_hash_points(G, H, pk, gamma, U, V)

        return c == c_prime

    