from Crypto.Hash import SHA256
class PoE(object):
    def __init__(self, publickKey, T, y, pi):
        self.publicKey = publickKey
        self.T = T
        self.y = y
        self.pi = pi
    
    @classmethod
    def from_dictionary(cls, params):
        return cls()

    def to_dictionary(self):
        return {}


class PoC(object):
    def __init__(self, publicKey, T, C, D, sigma):
        self.publicKey = publicKey
        self.T = T
        self.C = C
        self.D = D
        self.sigma = sigma
    
    def verify(self):
        h = SHA256.new()
        h.update(str(self.C).encode())
        h.update(str(self.D).encode())
        h = h.hexdigest()
        h = int(h, 16)

        return self.publicKey.verify(h, self.sigma)