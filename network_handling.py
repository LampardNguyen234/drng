import PDL_interface
import Requester_interface
import config

import struct
import json
import socket

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
    elif isinstance(python_object, Requester_interface.ReqDecryption):
        return  {'__class__': 'ReqDecryption',
                 '__value__': python_object.to_dictionary()}
    elif isinstance(python_object, Requester_interface.RespDecryption):
        return  {'__class__': 'RespDecryption',
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
    elif '__class__' in json_object:
        if json_object['__class__'] == 'ReqDecryption':
            return Requester_interface.ReqDecryption.from_dictionary(json_object['__value__'])
    elif '__class__' in json_object:
        if json_object['__class__'] == 'RespDecryption':
            return Requester_interface.RespDecryption.from_dictionary(json_object['__value__'])
    return json_object