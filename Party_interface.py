from Crypto.Hash import SHA256
import common
from ECVRF import ECVRF

class PoE(object):
    '''A model to encapsulate the PoE description
    '''

    def __init__(self, pubkey, T, y, pi):
        self.pubkey = pubkey
        self.T = T
        self.y = y
        self.pi = pi
    
    @staticmethod
    def verify(poe):
        """Verifies a PoE
        
        Arguments:\n
            poe -- the input PoE
        """
        return ECVRF.verify(poe.T, poe.pi, poe.pubkey, poe.y)
    
    @classmethod
    def from_dictionary(cls, params):
        """Parses a JSON string to an object of this class
        
        Arguments:\n
            params -- the JSON string
        """

        pubkey = params['pubkey']
        pubkey = common.parse_point(pubkey)
        T = params['T']
        y = params['y']
        pi = params['pi']
        return cls(pubkey, T, y, pi)

    def to_dictionary(self):
        """
        Serializes the object to JSON for transmitting through the network
        """
        return {'pubkey': self.pubkey.to_dictionary(), 'T': self.T, 'y': self.y, 'pi': self.pi}


class PoC(object):
    '''A model to encapsulate the PoC description
    '''

    def __init__(self, pubkey, T, C, D, sigma):
        self.pubkey = pubkey
        self.T = T
        self.C = C
        self.D = D
        self.sigma = sigma
    
    @staticmethod
    def verify(poc):
        """Verifies a PoC
        
        Arguments:\n
            poc -- the PoC
        """
        h = SHA256.new()
        h.update(str(poc.C).encode())
        h.update(str(poc.D).encode())
        h = h.hexdigest()
        h = int(h, 16)

        pubkey = common.create_pubkey_from_point(poc.pubkey)

        return pubkey.verify(h, poc.sigma)
    
    @classmethod
    def from_dictionary(cls, params):
        """Parses a JSON string to an object of this class
        
        Arguments:\n
            params -- the JSON string
        """

        pubkey = params['pubkey']
        pubkey = common.parse_point(pubkey)

        T = params['T']
        
        C = params['C']
        C = common.parse_point(C)

        D = params['D']
        D = common.parse_point(D)

        sigma = params['sigma']
        sigma = common.parse_signature(sigma)

        return cls(pubkey, T, C, D, sigma)

    def to_dictionary(self):
        """Serializes the object to JSON for transmitting through the network
        """
        return {'pubkey': self.pubkey.to_dictionary(), 'T': self.T,
        'C': self.C.to_dictionary(), 'D': self.D.to_dictionary(), 'sigma': self.sigma.to_dictionary()}