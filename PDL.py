from PDL_interface import *
import socket
import common
import config

def KickOff():
    """Kicks off the PDL. Creates/binds a socket and starts listening for any requests.
    """
    state = PDLState()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(config.PDL_ADDR)
    sock.listen()

    print("PDL started!!!")

    while True:
        conn, addr = sock.accept()
        msg = common.read_message(conn)
        if not msg:
            conn.close()
            continue
        HandleMessage(msg, conn, state)
        conn.close()

def HandlTicketRequest(msg, conn, state):
    """Handles the request for getting the Threshold. If not existed, return an error.
    
    Arguments:
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """

    #If the Threshold has been defined
    if not state.isExpired and state.currentTicket:
        common.write_message(conn, RespTicket(state.currentTicket))
    else:
        common.write_message(conn, common.RespError("The current ticket has not been defined yet!"))

def HandleMessage(msg, conn, state):
    """Handles received messages as appropriate
    
    Arguments:
        msg -- received message
        conn -- the connection socket
        state -- current state of the PDL
    """

    print("Received a new message: {}".format(msg))
    if msg['__class__'] == 'ReqGenTick':
        HandleGenerateTicket(msg['__value__'], conn, state)
    elif msg['__class__'] == 'ReqThreshold':
        HandleThresholdRequest(msg['__value__'], conn, state)
    elif msg['__class__'] == 'ReqPubKey':
        HandlePubKeyRequest(msg['__value__'], conn, state)
    elif msg['__class__'] == 'ReqTicket':
        HandlTicketRequest(msg['__value__'], conn, state)

def HandlePubKeyRequest(msg, conn, state):
    """Handles the request for getting the encryption key from requesters. If not existed, return an error.
    
    Arguments:
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """

    #If the Threshold has been defined
    if state.currentPubKey:
        common.write_message(conn, RespPubKey(state.currentPubKey))
    else:
        common.write_message(conn, common.RespError("The Requester has not connected yet!"))

def HandleThresholdRequest(msg, conn, state):
    """Handles the request for getting the Threshold. If not existed, return an error.
    
    Arguments:
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """

    #If the Threshold has been defined
    if state.currentThreshold:
        common.write_message(conn, RespThreshold(state.currentThreshold))
    else:
        common.write_message(conn, common.RespError("The Threshold has not been defined yet!"))

def HandleGenerateTicket(msg, conn, state):
    """Handles the request for generating new ticket from the Requester. If existed, return an error.
    
    Arguments:
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """

    #If the ticket has not been created or the current one has not been expired
    if state.isExpired:
        state.isExpired = False

        pubkey_X = msg['pubkey_X']
        pubkey_Y = msg['pubkey_Y']
        pubkey = common.CreatePoint(pubkey_X, pubkey_Y)

        nonce = msg['nonce']
        state.currentTicket = common.GenerateTicket(pubkey, nonce)
        state.currentPubKey = pubkey
        print("State", state)
        common.write_message(conn, RespGenTick(state.currentTicket))
    else:
        common.write_message(conn, common.RespError("The current ticket has not been expired yet!"))

class PDLState:
    """
    A model to encapsulate PDL state
    """
    def __init__(self):
        self.currentThreshold = None
        self.currentTicket = None
        self.isExpired = True
        self.numParty = 0
        self.numContributor = 0
        self.currentPubKey = None

    def __str__(self):
        return "<PDLState: currentThreshold: {}, currentTicket: {}, isExpired : {}, parties: {}, contributors: {}, pubkey: {}>".format(
            hex(self.currentThreshold), hex(self.currentTicket), self.isExpired,
            self.numParty, self.numContributor, self.currentPubKey)

if __name__ == "__main__":
    KickOff()