from common import *
from network_handling import *
from ecdsa.ecdsa import Private_key, Public_key
from ECVRF import ECVRF
from Crypto.Random import random
from Crypto.Hash import SHA256
import PDL_interface
from Party_interface import *

class Party(object):
    def __init__(self, private_key = None):
        if private_key is None:
            d = random_order()
            point = d*G
            self.public_key = Public_key(G, point)
            self.private_key = Private_key(self.public_key, d)
        else:
            self.private_key = private_key
            self.public_key = self.private_key.public_key
        
        self.VRF = ECVRF(self.private_key)

    def check_eligibility(self, T, Th):
        """Checks if the party is eligible to contribute or not (Algorithm 3)
        
        Arguments:\n
            T -- The input ticket
            Th -- The threshold
        """
        out = self.VRF.prove(T)
        y = out['y']
        pi = out['pi']
        if y < Th:
            return True, y, pi
        else:
            return False, None, None

    def contribute(self, T, Th, Y):
        """A party checks his eligibility. If eligible, he has to contribute a number subject to the
        ticket T (Algorithm 4). 
        
        Arguments:\n
            T -- The input ticket
            Th -- The threshold
            Y -- The encryption key of the requester
        """
        eligible, y, pi = self.check_eligibility(T, Th)
        
        if eligible:
            x = random_order()
            M = x*G

            print("\nYour contribution is: M = {}".format(M))

            k = random_order()
            C = k*G
            D = k*Y + M

            print("C =", C)
            print("D =", D)

            h = SHA256.new()
            h.update(str(C).encode())
            h.update(str(D).encode())
            h = h.hexdigest()
            h = int(h, 16)

            sigma = self.private_key.sign(h, random_order())

            return PoE(self.public_key.point, T, y, pi), PoC(self.public_key.point, T, C, D, sigma)
        else:
            return None, None

    def kick_off(self, T=None, Th=None, Y=None):
        """Starts the operation of the party

        Arguments:\n
            T -- the current ticket
            Th -- the current threshold
            Y -- the current public key of the Requester
        """
        if T is None:
            sock_to_PDL = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_to_PDL.connect(config.PDL_ADDR)
            req = PDL_interface.ReqTicket()
            write_message(sock_to_PDL, req)
            resp = read_message(sock_to_PDL)

            if isinstance(resp, RespError):
                print(resp)
            elif resp['__class__'] == 'RespTicket':
                T = resp['__value__']['ticket']
                Th = resp['__value__']['threshold']

                Y = resp['__value__']['pubkey']
                Y = common.parse_point(Y)

        self.poe, self.poc = self.contribute(T, Th, Y)

        if self.poc is None:
            print("\nYou are not eligible to contribute!")
        else:
            resp = self.send_contribution()
            if not isinstance(resp, RespError):
                print("\nYour contribution has been received!")
            else:
                print(resp)

    def send_contribution(self):
        """Sends the contribution, poe and poc to the PDL.
        """
        sock_to_PDL = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_to_PDL.connect(config.PDL_ADDR)
        req = PDL_interface.ReqContribution(self.poe, self.poc)
        write_message(sock_to_PDL, req)
        resp = read_message(sock_to_PDL)
        return resp

if __name__ == '__main__':
    party = Party()
    party.kick_off()