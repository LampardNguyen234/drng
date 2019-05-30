"""
Common models and utility functions
"""

import struct
import json
import socket

import config
from Crypto.Hash import SHA256
from ecdsa.ecdsa import curve_256, generator_256, Signature, Public_key
from ecdsa.ellipticcurve import Point
from Crypto.Random import random
import PDL_interface

CURVE = curve_256
G = generator_256
ORDER = G.order()

class RespError:
    """
    represents an error response from the server
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "<RespError: {}>".format(self.msg)

    @classmethod
    def from_dictionary(cls, params):
        msg = params['msg']
        return cls(msg)

    def to_dictionary(self):
        return {'msg': self.msg}

def ECVRF_hash_to_curve(alpha, pk=None):
    """Hash an integer in to the target curve
    
    Arguments:
        y  -- An additional input (usually the public key)
        alpha [Int] -- An input integer
    
    Returns:
        alpha * Generator + Y
    """
    if pk is None:
        return alpha * G
    else:
        return alpha*G + pk

def ECVRF_hash_points(g, h, pk, gamma, gk, hk):
    """Calculate the hash of many points, used in the VRF
    
    Arguments:
        g, h, pk, gamma, gk, hk -- Points on curve
    """
    ha = SHA256.new()
    ha.update(str(g).encode())
    ha.update(str(h).encode())
    ha.update(str(pk).encode())
    ha.update(str(gamma).encode())
    ha.update(str(gk).encode())
    ha.update(str(hk).encode())

    return int(ha.hexdigest(), 16) % ORDER


def I2OSP(x, xLen):
    if x >= 256**xLen:
        raise ValueError("integer too large")
    digits = []

    while x:
        digits.append(int(x % 256))
        x //= 256
    for i in range(xLen - len(digits)):
        digits.append(0)
    return digits[::-1]

def OS2IP(X):
    xLen = len(X)
    X = X[::-1]
    x = 0
    for i in range(xLen):
        x += X[i] * 256^i
    return x

def EC2OSP(P):
    x = P.x()
    y = P.y()
    return I2OSP(x, 32) + I2OSP(y, 32)


def CreatePointFromXY(Px, Py):
    return Point(CURVE, Px, Py)


def ComputeThreshold(k, n, l):    
    return k*(2**l)//(n+1)

def TallyContribute(C, D):
    if len(C) != len(D):
        return None
    C_temp = C[0]
    D_temp = D[0]
    for i in range(1, len(C)):
        C_temp = C_temp + C[i]
        D_temp = D_temp + D[i]
    
    return C_temp, D_temp


def VerifyZKP(Y, M, C, D, c, z):
    B0 = z*G + (ORDER - c)*Y
    D2 = D + (ORDER - 1)*M
    B1 = z*C + (ORDER - c)* D2

    h = SHA256.new()
    h.update(str(Y).encode())
    h.update(str(C).encode())
    h.update(str(D2).encode())
    h.update(str(B0).encode())
    h.update(str(B1).encode())

    return c == int(h.hexdigest(), 16)

def GenerateTicket(publicKey, nonce):
    h = SHA256.new()
    h.update(str(publicKey).encode())
    h.update(str(nonce).encode())
    return int(h.hexdigest(), 16)

def RandomOrder():
    return random.randint(0, ORDER)

def CreateSignatureFromrs(r, s):
    return Signature(r,s)

def CreatePublicKeyFromPoint(P):
    return Public_key(G, P)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def read_message(conn):
    """
    Reads message from a socket

    :param conn: the socket to read from
    :return: length of the message OR None if message length cannot be read
    """

    buf = _read_socket_buf(conn, 4)
    if not buf:
        print("Error: Unable to read message size")
        return None

    msg_size = struct.unpack("!i", buf)[0]
    # print("Length of the message is: {}".format(msg_size))

    buf = _read_socket_buf(conn, msg_size)
    if not buf:
        print("Error: Unable to read message of length {}".format(msg_size))
        return None

    obj = json.loads(buf.decode("utf-8"), object_hook=_from_json)
    return obj


def write_message(conn, obj):
    """
    Writes a message to the socket

    :param conn: the socket to write to
    :param obj: any python object supported by pickle, it will be written to the socket
    :return:
    """

    msg = json.dumps(obj, default=_to_json).encode('utf-8')
    msg_size = len(msg)
    buf_to_write = struct.pack("!i", msg_size) + msg
    conn.sendall(buf_to_write)


def get_public_key_from_requester():
    return 10*G

# --- Private ---


def _read_socket_buf(conn, n):
    """
    Reads buffer from conn up to n bytes

    :param conn: the socket to read from
    :param n: number of bytes to read
    :return: the buffer OR None
    """
    buf = b''
    while len(buf) < n:
        new_data = conn.recv(n - len(buf))
        if not new_data:
            return None
        buf += new_data
    return buf


def _to_json(python_object):
    """
    converts request and response objects used in the system to python serializable objects

    :param python_object: object to convert to json serializable object
    :return: json serializable representation of `python_object`
    """
    if isinstance(python_object, RespError):
        return  {'__class__': 'RespError',
                 '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, PDL_interface.ReqGenTick):
        return  {'__class__': 'ReqGenTick',
                 '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, PDL_interface.RespGenTick):
        return  {'__class__': 'RespGenTick',
                 '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, PDL_interface.ReqThreshold):
        return  {'__class__': 'ReqThreshold',
                 '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, PDL_interface.RespThreshold):
        return  {'__class__': 'RespThreshold',
                 '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, PDL_interface.ReqPubKey):
        return  {'__class__': 'ReqPubKey',
                 '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, PDL_interface.RespPubKey):
        return  {'__class__': 'RespPubKey',
                 '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, PDL_interface.ReqTicket):
        return  {'__class__': 'ReqTicket',
                 '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, PDL_interface.RespTicket):
        return  {'__class__': 'RespTicket',
                 '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, PDL_interface.ReqContribution):
        return  {'__class__': 'ReqContribution',
                 '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, PDL_interface.RespContribution):
        return  {'__class__': 'RespContribution',
                 '__value__': python_object.to_dictionary()}
    
    raise TypeError(repr(python_object) + ' is not JSON serializable')


def _from_json(json_object):
    """
    converts json object to python object
    :param json: object to convert from
    :return: python object corresponding to json object
    """

    if '__class__' in json_object:
        if json_object['__class__'] == 'RespError':
            return RespError.from_dictionary(json_object['__value__'])
    elif '__class__' in json_object:
        if json_object['__class__'] == 'ReqGenTick':
            return PDL_interface.ReqGenTick.from_dictionary(json_object['__value__'])
    elif '__class__' in json_object:
        if json_object['__class__'] == 'RespGenTick':
            return PDL_interface.RespGenTick.from_dictionary(json_object['__value__'])
    elif '__class__' in json_object:
        if json_object['__class__'] == 'ReqThreshold':
            return PDL_interface.ReqThreshold.from_dictionary(json_object['__value__'])
    elif '__class__' in json_object:
        if json_object['__class__'] == 'RespThreshold':
            return PDL_interface.RespThreshold.from_dictionary(json_object['__value__'])
    elif '__class__' in json_object:
        if json_object['__class__'] == 'ReqPubKey':
            return PDL_interface.ReqPubKey.from_dictionary(json_object['__value__'])
    elif '__class__' in json_object:
        if json_object['__class__'] == 'RespPubKey':
            return PDL_interface.RespPubKey.from_dictionary(json_object['__value__'])
    elif '__class__' in json_object:
        if json_object['__class__'] == 'ReqTicket':
            return PDL_interface.ReqTicket.from_dictionary(json_object['__value__'])
    elif '__class__' in json_object:
        if json_object['__class__'] == 'RespTicket':
            return PDL_interface.RespTicket.from_dictionary(json_object['__value__'])
    elif '__class__' in json_object:
        if json_object['__class__'] == 'ReqContribution':
            return PDL_interface.ReqContribution.from_dictionary(json_object['__value__'])
    elif '__class__' in json_object:
        if json_object['__class__'] == 'RespContribution':
            return PDL_interface.RespContribution.from_dictionary(json_object['__value__'])
    return json_object
