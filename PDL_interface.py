"""Contains request and response objects for Public Distributed Ledger (PDL)
"""

import common
from Party_interface import PoC, PoE
class ReqGenTick:
    """Request to generate a ticket
    """
    def __init__(self, pubkey, nonce):
        self.pubkey = pubkey
        self.nonce = nonce

    def __repr__(self):
        return "<ReqGenTick: pubkey: {}, nonce: {}>".format(self.pubkey, self.nonce)

    @classmethod
    def from_dictionary(cls, params):
        pubkey = params['pubkey']
        pubkey = common.parse_point(pubkey)

        nonce = params['nonce']
        
        return cls(pubkey, nonce)

    def to_dictionary(self):
        return {'pubkey': self.pubkey, 'nonce': self.nonce}

class RespGenTick:
    """Response to generate a ticket
    """
    def __init__(self, ticket):
        self.ticket = ticket

    def __repr__(self):
        return "<RespGenTick: ticket: {}>".format(self.ticket)

    @classmethod
    def from_dictionary(cls, params):
        ticket = params['ticket']
        return cls(ticket)

    def to_dictionary(self):
        return {'ticket': self.ticket}

class ReqThreshold:
    """Request to get the Threshold
    """
    def __repr__(self):
        return "<ReqThreshold: Request for the Threshold>"

    @classmethod
    def from_dictionary(cls, params):
        return cls()

    def to_dictionary(self):
        return {}

class RespThreshold:
    """Response to get the Threshold
    """
    def __init__(self, threshold):
        self.threshold = threshold

    def __repr__(self):
        return "<RespThreshold: threshold: {}>".format(self.threshold)

    @classmethod
    def from_dictionary(cls, params):
        threshold = params['threshold']
        return cls(threshold)

    def to_dictionary(self):
        return {'threshold': self.threshold}

class ReqTicket:
    """Request to get the current ticket
    """
    def __repr__(self):
        return "<ReqTicket: Request for the current ticket>"

    @classmethod
    def from_dictionary(cls, params):
        return cls()

    def to_dictionary(self):
        return {}

class RespTicket:
    """Response to get the current ticket
    """
    def __init__(self, ticket, threshold, pubkey):
        self.ticket = ticket
        self.threshold = threshold
        self.pubkey = pubkey

    def __repr__(self):
        return "<RespTicket: ticket: {}, threshold: {}, pubkey: {}>".format(self.ticket, self.threshold, self.pubkey)

    @classmethod
    def from_dictionary(cls, params):
        ticket = params['ticket']
        threshold = params['threshold']
        pubkey = params['pubkey']
        return cls(ticket, threshold)

    def to_dictionary(self):
        return {'ticket': self.ticket, 'threshold': self.threshold, 'pubkey': self.pubkey.to_dictionary()}

class ReqPubKey:
    """Request to get the encryption key of the requester
    """
    def __repr__(self):
        return "<ReqPubKey: Request for the encryption key>"

    @classmethod
    def from_dictionary(cls, params):
        return cls()

    def to_dictionary(self):
        return {}

class RespPubKey:
    """Response to generate a ticket
    """
    def __init__(self, pubkey_X, pubkey_Y):
        self.pubkey_X = pubkey_X
        self.pubkey_Y = pubkey_Y

    def __repr__(self):
        return "<RespPubKey: pubkey_X: {}, pubkey_Y: {}>".format(self.pubkey_X, self.pubkey_Y)

    @classmethod
    def from_dictionary(cls, params):
        pubkey_X = params['pubkey_X']
        pubkey_Y = params['pubkey_Y']
        return cls(pubkey_X, pubkey_Y)

    def to_dictionary(self):
        return {'pubkey_X': self.pubkey_X, 'pubkey_Y': self.pubkey_Y}


class ReqContribution:
    """Party sends a contribution to the PDL
    """
    def __init__(self, poe, poc):
        self.poe = poe;
        self.poc = poc;

    def __repr__(self):
        return "<ReqContribution: PoE: {}, PoC: {})>".format(
            self.poe.to_dictionary(), self.poc.to_dictionary())

    @classmethod
    def from_dictionary(cls, params):
        poe = params['PoE']
        poe = PoE.from_dictionary(poe)

        poc = params['PoC']
        poc = PoC.from_dictionary(poc)

        return cls(poe, poc)

    def to_dictionary(self):
        return {'PoE': self.poe.to_dictionary(), 'PoC': self.poc.to_dictionary()}

class RespContribution:
    """Response to a contribution from the PDL to the party
    """
    def __init__(self, msg):
        self.msg = msg
    
    def __repr__(self):
        return "<RespContribution: {}>".format(self.msg)
    
    @classmethod
    def from_dictionary(cls, params):
        msg = params['msg']
        return cls(msg)

    def to_dictionary(self):
        return {'msg': self.msg}

