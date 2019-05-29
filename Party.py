from common import *
from ecdsa.ecdsa import Private_key, Public_key
from ECVRF import ECVRF
from Crypto.Random import random
from Crypto.Hash import SHA256
import PDL_interface

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
        """A party checks if he is eligible to contribute or not (Algorithm 3)
        
        Arguments:
            T -- The input ticket
            Th -- The threshold
        """
        out = self.VRF.Prove(T)
        y = out['y']
        pi = out['pi']
        if beta < Th:
            return True, y, pi
        else:
            return False, None, None

    def Contribute(self, T, Th, Y):
        """A party checks his eligibility. If eligible, he has to contribute a number subject to the
        ticket T (Algorithm 4). 
        
        Arguments:
            T -- The input ticket
            Th -- The threshold
            Y -- The encryption key of the requester
        """
        eligible, y, pi = self.CheckEligibility(T, Th)
        
        if eligible:
            # Y = get_public_key_from_requester()
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

            return PoE(self.private_key.public_key, T, y, pi), PoC(self.public_key, T, C, D, sigma)
        else:
            return None, None

def KickOff():
    party = Party()

    sock_to_PDL = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_to_PDL.connect(config.PDL_ADDR)
    req = PDL_interface.ReqPubKey()
    write_message(sock_to_PDL, req)
    resp = read_message(sock_to_PDL)
    print(resp)

if __name__ == '__main__':
    KickOff()