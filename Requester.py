from common import *
from network_handling import *
from Crypto.Random import random
import config
import PDL_interface
from Requester_interface import *

class Requester(object):
    
    def __init__(self, x=None):
        if x is None:
            self.x = random_order()
        else:
            self.x = x
        self.Y = self.x * G
        pass
    
    def __repr__(self):
        return "<Requester: privkey: {}, pubkey: {}>".format(self.x, self.Y)

    def decrypt(self, C, D):
        """Decrypts the input ciphertext using secret key x
        
        Arguments:\n
            C -- the first part of the ciphertext
            D -- the second part of the ciphertext
        
        Returns:\n
            M -- the decrypted point
            (c, z) -- the proof of proper decryption for M
        """
        M = D + (ORDER-self.x)*C

        print("M =", M)

        D2 = D + (ORDER - 1)*M

        r = random_order()

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

def kick_off():
    '''Kicks off the Requester server
    '''
    requester = Requester()

    print(requester)
    
    sock_to_PDL = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_to_PDL.connect(config.PDL_ADDR)
    req = PDL_interface.ReqGenTick(requester.Y, random.randint(0, 2**256))
    write_message(sock_to_PDL, req)
    resp = read_message(sock_to_PDL)

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
    """Handles received messages as appropriate class
    
    Arguments:\n
        msg -- received message
        conn -- the connection socket
        requester -- the Requester
    """

    print("\nReceived a new message:\n{}".format(msg))
    if msg['__class__'] == 'ReqDecryption':
        msg = msg['__value__']
        C = msg['C']
        D = msg['D']
        C = parse_point(C)
        D = parse_point(D)

        print("\nReceived a new tallied contribution:")
        print("C = {}\nD = {}".format(C, D))
        out = requester.decrypt(C, D)

        req = RespDecryption(out[0], out[1], out[2])
        write_message(conn, req)
        print("\nThe final outcome is:\n{}".format(out[0]))
        exit()

if __name__ == '__main__':
    kick_off()