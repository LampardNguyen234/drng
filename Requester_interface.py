import common
class ReqDecryption(object):
    def __init__(self, C, D):
        self.C = C
        self.D = D
    
    @classmethod
    def from_dictionary(cls, params):
        C = params['C']
        D = params['D']

        C = common.parse_point(C)
        D = common.parse_point(D)
        return cls(C, D)

    def to_dictionary(self):
        return {'C': self.C.to_dictionary(), 'D': self.D.to_dictionary()}


class RespDecryption(object):
    def __init__(self, M, c, z):
        self.M = M
        self.c = c
        self.z = z
    
    @classmethod
    def from_dictionary(cls, params):
        M = params['M']
        c = params['c']
        z = params['z']

        M = common.parse_point(M)

        return cls(M, c, z)

    def to_dictionary(self):
        return {'M': self.M.to_dictionary(), 'c': self.c, 'z': self.z}