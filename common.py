"""
Common models and utility functions
"""

import struct
import json
import socket

import config
from Crypto.Hash import SHA256
from ecdsa.ecdsa import *

CURVE = curve_256
G = generator_256
ORDER = G.order()


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

def verify_blind_signature(m, r, s):
    Q = get_public_key_from_em().point

    X = modinv(f(m), ORDER) * (s*G + (ORDER - f(r))*Q)

    return X.x() == r


def get_public_key_from_em():
    """
    Gets public keys from the EM

    :return: public keys
    """
    sock_to_em = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_to_em.connect(config.EM_ADDR)
    write_message(sock_to_em, em_interface.ReqPublicKeys())
    pub_keys = read_message(sock_to_em)
    # socket will be closed by the EM server
    return pub_keys

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
    elif isinstance(python_object, em_interface.ReqPublicKeys):
        return {'__class__': 'em_interface.ReqPublicKeys',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, em_interface.RespPublicKeys):
        return {'__class__': 'em_interface.RespPublicKeys',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, em_interface.ReqBlindSign):
        return {'__class__': 'em_interface.ReqBlindSign',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, em_interface.RespBlindSign):
        return {'__class__': 'em_interface.RespBlindSign',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, bb_interface.ReqCastVote):
        return {'__class__': 'bb_interface.ReqCastVote',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, bb_interface.RespCastVoteSuccess):
        return {'__class__': 'bb_interface.RespCastVoteSuccess',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, bb_interface.RespVotingClosed):
        return {'__class__': 'bb_interface.RespVotingClosed',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, bb_interface.ReqCloseVoting):
        return {'__class__': 'bb_interface.ReqCloseVoting',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, em_interface.ReqLogin):
        return {'__class__': 'em_interface.ReqLogin',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, em_interface.RespLogin):
        return {'__class__': 'em_interface.RespLogin',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, bb_interface.ReqKeyVote):
        return {'__class__': 'bb_interface.ReqKeyVote',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, bb_interface.RespKeyVoteSuccess):
        return {'__class__': 'bb_interface.RespKeyVoteSuccess',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, bb_interface.ReqAllVote):
        return {'__class__': 'bb_interface.ReqAllVote',
                '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, bb_interface.RespAllVote):
        return {'__class__': 'bb_interface.RespAllVote',
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
        elif json_object['__class__'] == 'em_interface.ReqPublicKeys':
            return em_interface.ReqPublicKeys.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'em_interface.RespPublicKeys':
            return em_interface.RespPublicKeys.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'em_interface.ReqBlindSign':
            return em_interface.ReqBlindSign.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'em_interface.RespBlindSign':
            return em_interface.RespBlindSign.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'bb_interface.ReqCastVote':
            return bb_interface.ReqCastVote.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'bb_interface.RespCastVoteSuccess':
            return bb_interface.RespCastVoteSuccess.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'bb_interface.RespVotingClosed':
            return bb_interface.RespVotingClosed.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'bb_interface.ReqCloseVoting':
            return bb_interface.ReqCloseVoting.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'em_interface.ReqLogin':
            return em_interface.ReqLogin.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'em_interface.RespLogin':
            return em_interface.RespLogin.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'bb_interface.ReqKeyVote':
            return bb_interface.ReqKeyVote.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'bb_interface.RespKeyVoteSuccess':
            return bb_interface.RespKeyVoteSuccess.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'bb_interface.ReqAllVote':
            return bb_interface.ReqAllVote.from_dictionary(json_object['__value__'])
        elif json_object['__class__'] == 'bb_interface.RespAllVote':
            return bb_interface.RespAllVote.from_dictionary(json_object['__value__'])

    return json_object
