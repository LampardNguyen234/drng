"""
Contains request and response objects for Public Distributed Ledger (PDL)
"""
class ReqGenTick:
    """
    Request to generate a ticket
    """
    def __init__(self, pubkey, nonce):
        self.pubkey = pubkey
        self.nonce = nonce

    def __repr__(self):
        return "<ReqGenTick: pubkey: {}, nonce: {}>".format(self.pubkey, self.nonce)

    @classmethod
    def from_dictionary(cls, params):
        pubkey = params['pubkey']
        nonce = params['nonce']
        return cls(pubkey, nonce)

    def to_dictionary(self):
        return {'pubkey': self.pubkey, 'nonce': self.nonce}

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