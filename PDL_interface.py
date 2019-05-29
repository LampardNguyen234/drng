"""
Contains request and response objects for Public Distributed Ledger (PDL)
"""
class ReqGenTick:
    """
    Request to generate a ticket
    """
    def __init__(self, pubkey_X, pubkey_Y, nonce):
        self.pubkey_X = pubkey_X
        self.pubkey_Y = pubkey_Y
        self.nonce = nonce

    def __repr__(self):
        return "<ReqGenTick: pubkey: ({}, {}), nonce: {}>".format(self.pubkey_X, self.pubkey_Y, self.nonce)

    @classmethod
    def from_dictionary(cls, params):
        pubkeyX = params['pubkey_X']
        pubkeyY = params['pubkey_Y']
        nonce = params['nonce']
        return cls(pubkey_X, pubkey_Y, nonce)

    def to_dictionary(self):
        return {'pubkey_X': self.pubkey_X, 'pubkey_Y': self.pubkey_Y, 'nonce': self.nonce}

class RespGenTick:
    """
    Response to generate a ticket
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
    """
    Request to get the Threshold
    """
    def __repr__(self):
        return "<ReqThreshold: Request for the Threshold>"

    @classmethod
    def from_dictionary(cls, params):
        return cls()

    def to_dictionary(self):
        return {}

class RespThreshold:
    """
    Response to generate a ticket
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

class ReqPubKey:
    """
    Request to get the encryption key of the requester
    """
    def __repr__(self):
        return "<ReqPubKey: Request for the encryption key>"

    @classmethod
    def from_dictionary(cls, params):
        return cls()

    def to_dictionary(self):
        return {}

class RespPubKey:
    """
    Response to generate a ticket
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