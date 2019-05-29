from common import *
from ecdsa.ecdsa import *
from Crypto.Hash import SHA256
from party import Party
from ECVRF import *


x = 10
Y = x*G

print(EC2OSP(Y))

# x = RandomOrder()
# print(x)
