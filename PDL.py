from PDL import *
import socket
import common
import config

def KickOff():
    """Kicks off the PDL. Creates/binds a socket and starts listening for any requests.
    """
    global state
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
        HandleMessage(msg, conn)
        conn.close()

def HandleMessage(msg, conn):
    """Handles received messages as appropriate
    
    Arguments:
        msg -- received message
        conn -- the connection socket
    """

    print("Received a new message: {}".format(msg))
    if isinstance(msg, ReqGenTick):
        HandleGenerateTicket(msg, conn)


def HandleGenerateTicket(msg, conn):
    if state.isExpired:
        state.isExpired = False
        pubkey = msg['pubkey']
        nonce = msg['nonce']
        state.currentTicket = common.GenerateTicket(pubkey, nonce)
        state.currentThreshold = common.ComputeThreshold(config.EXPECTED_NUM_CONTRIBUTORS, config.NUM_PARTIES, 256)
        state.currentPubKey = pubkey
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
        return "<PDLState: {}, {}, {}, {}, {}, {}>".format(self.currentThreshold, self.currentTicket, self.isExpired,
            self.numParty, self.numContributor, self.currentPubKey)


if __name__ == "__main__":
    KickOff()