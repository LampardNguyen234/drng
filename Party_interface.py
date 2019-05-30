from Crypto.Hash import SHA256
import common
class PoE(object):
    def __init__(self, publickKey, T, y, pi):
        self.publicKey = publickKey
        self.T = T
        self.y = y
        self.pi = pi
    
    @classmethod
    def from_dictionary(cls, params):
        pubkey_X = params['pubkey_X']
        pubkey_Y = params['pubkey_Y']
        T = params['T']
        y = params['y']
        pi = params['pi']
        pubkey = common.create_pubkey_from_point(common.create_point_from_XY(pubkey_X, pubkey_Y))
        return cls(pubkey, T, y, pi)

    def to_dictionary(self):
        return {'pubkey_X': self.publicKey.point.x(), 'pubkey_Y': self.publicKey.point.y(), 'T': self.T,
        'y': y, 'pi': pi}


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
    
    @classmethod
    def from_dictionary(cls, params):
        pubkey = common.EC_point_from_JSON(params['pubkey'])
        T = params['T']
        y = params['y']
        pi = params['pi']
        return cls(pubkey, T, y, pi)

    def to_dictionary(self):
        return {'pubkey': self.publicKey.point.to_dictionary(), 'T': self.T,
        'C': C.to_dictionary(), 'D': D.to_dictionary(), 'sigma': sigma.to_dictionary()}