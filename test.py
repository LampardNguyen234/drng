from common import *
from ecdsa.ecdsa import *
from Crypto.Hash import SHA256
from party import Party


x = RandomOrder()
Y = x*G
T = GenerateTicket(Y, RandomOrder())
print(T)

p = Party()

poc = p.Contribute(T)

print(poc)

print(poc.verify())

# x = RandomOrder()
# print(x)
