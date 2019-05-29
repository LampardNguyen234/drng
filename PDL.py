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


def HandleGenerateTicket(msg, conn, state):
    if state.isExpired:
        state.isExpired = False

        pubkey_X = msg['pubkey_X']
        pubkey_Y = msg['pubkey_Y']
        pubkey = common.CreatePoint(pubkey_X, pubkey_Y)

        nonce = msg['nonce']
        state.currentTicket = common.GenerateTicket(pubkey, nonce)
        state.currentThreshold = common.ComputeThreshold(config.EXPECTED_NUM_CONTRIBUTORS, config.NUM_PARTIES, 256)
        state.currentPubKey = pubkey
        print("State", state)
        common.write_message(conn, RespGenTick(state.currentTicket))

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