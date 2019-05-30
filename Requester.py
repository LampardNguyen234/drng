from common import *
from networkHandling import *
from Crypto.Random import random
import config
import PDL_interface
from Requester_interface import *

class Requester(object):
    
    def __init__(self, x=None):
        if x is None:
            self.x = RandomOrder()
        else:
            self.x = x
        self.Y = self.x * G
        pass
    
    def __repr__(self):
        return "<Requester: privkey: {}, pubkey: {}>".format(self.x, self.Y)

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

        return (M, c, z)

def KickOff():
    requester = Requester()

    print(requester)
    
    sock_to_PDL = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_to_PDL.connect(config.PDL_ADDR)
    req = PDL_interface.ReqGenTick(requester.Y.x(), requester.Y.y(), random.randint(0, 2**256))
    write_message(sock_to_PDL, req)
    resp = read_message(sock_to_PDL)
    
    print(resp)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(config.REQUESTER_ADDR)
    sock.listen()

    while True:
        conn, addr = sock.accept()
        msg = read_message(conn)
        if not msg:
            conn.close()
            continue
        HandleMessage(msg, conn, requester)
        conn.close()

def HandleMessage(msg, conn, requester):
    print("Received a new message: {}".format(msg))
    if msg['__class__'] == 'ReqDecryption':
        msg = msg['__value__']
        C = msg['C']
        D = msg['D']
        C = CreatePointFromXY(C['x'], C['y'])
        D = CreatePointFromXY(D['x'], D['y'])
        print("C =", C)
        print("D =", D)
        out = requester.decrypt(C, D)
        print(out)

        req = RespDecryption(out[0], out[1], out[2])
        write_message(conn, req)

if __name__ == '__main__':
    KickOff()