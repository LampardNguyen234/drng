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

        C = common.CreatePointFromXY(C_X, C_Y)
        D = common.CreatePointFromXY(D_X, D_Y)
        return cls(C, D)

    def to_dictionary(self):
        return {'C': self.C.to_dictionary(), 'D': self.C.to_dictionary()}


class RespDecryption(object):
    def __init__(self, M, c, z, B0, B1):
        self.M = M
        self.B0 = B0
        self.B1 = B1
        self.c = c
        self.z = z
    
    @classmethod
    def from_dictionary(cls, params):
        M_X = params['M']['x']
        M_Y = params['M']['y']
        B0_X = params['B0']['x']
        B0_Y = params['B0']['y']
        B1_X = params['B1']['x']
        B1_Y = params['B1']['y']
        c = params['c']
        z = params['z']

        M = common.CreatePointFromXY(M_X, M_Y)
        B0 = common.CreatePointFromXY(B0_X, B0_Y)
        B1 = common.CreatePointFromXY(B1_X, B1_Y)

        return cls(M, c, z, B0, B1)

    def to_dictionary(self):
        return {'M': self.M.to_dictionary(), 'B0': self.B0.to_dictionary(),
        'B1': self.B1.to_dictionary(), 'c': self.c, 'z': self.z}