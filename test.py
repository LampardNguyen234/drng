from common import *
from ecdsa.ecdsa import *
from Crypto.Hash import SHA256
from party import Party
from ECVRF import ECVRF


p = Party()

x = p.VRF.Prove(10)

print (ECVRF.Verify())
# x = RandomOrder()
# print(x)
