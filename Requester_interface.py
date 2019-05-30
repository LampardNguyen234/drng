import common
class ReqDecryption(object):
    def __init__(self, C, D):
        self.C = C
        self.D = D
    
    @classmethod
    def from_dictionary(cls, params):
        C_X = params['C']['x']
        C_Y = params['D']['y']
        D_X = params['D']['x']
        D_Y = params['D']['y']

        C = common.create_point_from_XY(C_X, C_Y)
        D = common.create_point_from_XY(D_X, D_Y)
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
        M_X = params['M']['x']
        M_Y = params['M']['y']
        c = params['c']
        z = params['z']

        M = common.create_point_from_XY(M_X, M_Y)

        return cls(M, c, z)

    def to_dictionary(self):
        return {'M': self.M.to_dictionary(), 'c': self.c, 'z': self.z}