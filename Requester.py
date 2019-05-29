from common import *
from Crypto.Random import random
import config
import PDL_interface

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

def KickOff():
    requester = Requester()
    sock_to_PDL = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_to_PDL.connect(config.PDL_ADDR)
    req = PDL_interface.ReqGenTick(requester.Y.x(), requester.Y.y(), random.randint(0, 2**256))
    write_message(sock_to_PDL, req)
    resp = read_message(sock_to_PDL)
    print(resp)

if __name__ == '__main__':
    KickOff()