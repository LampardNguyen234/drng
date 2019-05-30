from common import *
from ecdsa.ecdsa import *
from Crypto.Hash import SHA256
from ECVRF import ECVRF
from Requester import Requester

r = Requester()

X = random.randint(0, 2**254)*G
Y = r.Y

print("X =", X)
k = random.randint(0, 2**254)
C = k*G
D = k*Y + X 

M = r.decrypt(C, D)
print("M =", VerifyZKP(Y, M[0], C, D, M[1], M[2]))
# x = RandomOrder()
# print(x)
