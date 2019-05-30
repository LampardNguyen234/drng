from PDL_interface import *
import socket
import common
import networkHandling
import config
from Party_interface import PoC, PoE
from Crypto.Random import random
import Requester_interface

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
        msg = networkHandling.read_message(conn)
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
    elif msg['__class__'] == 'ReqThreshold':
        HandleThresholdRequest(msg['__value__'], conn, state)
    elif msg['__class__'] == 'ReqPubKey':
        HandlePubKeyRequest(msg['__value__'], conn, state)
    elif msg['__class__'] == 'ReqTicket':
        HandleTicketRequest(msg['__value__'], conn, state)
    elif msg['__class__'] == 'ReqContribution':
        HandleContribution(msg['__value__'], conn, state)

def HandleContribution(msg, conn, state):
    """Handles contribution from party.
    Arguments:
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """

    #If the Threshold has been defined
    if not state.isExpired:
        pubkey_X = msg['pubkey']['x']
        pubkey_Y = msg['pubkey']['y']
        pubkey = common.CreatePointFromXY(pubkey_X, pubkey_Y)

        C_X = msg['C']['x']
        C_Y = msg['C']['y']
        C = common.CreatePointFromXY(C_X, C_Y)

        D_X = msg['D']['x']
        D_Y = msg['D']['y']
        D = common.CreatePointFromXY(D_X, D_Y)

        print("C =", C)
        print("D =", D)

        sigma_r = msg['sigma_r']
        sigma_s = msg['sigma_s']

        pubkey = common.CreatePublicKeyFromPoint(pubkey)
        sigma = common.CreateSignatureFromrs(sigma_r, sigma_s)
        poc = PoC(pubkey, state.currentTicket, C, D, sigma)

        if poc.verify():
            state.numContributor += 1
            if state.currentC is None:
                state.currentC = C
                state.currentD = D
            else:
                state.currentC = state.currentC + C
                state.currentD = state.currentD + D
            networkHandling.write_message(conn, RespContribution("Contribution success!"))
            if state.numContributor == state.numParty:
                print("Contribution complete!")

                sock_to_req = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_to_req.connect(config.REQUESTER_ADDR)
                req = Requester_interface.ReqDecryption(state.currentC, state.currentD)
                networkHandling.write_message(sock_to_req, req)
                
                resp = networkHandling.read_message(sock_to_req)
                resp = resp['__value__']
                
                M = resp['M']
                c = resp['c']
                z = resp['z']

                M = common.CreatePointFromXY(M['x'], M['y'])

                if common.VerifyZKP(state.currentPubKey, M, state.currentC, state.currentD, c, z):
                    print("The final outcome is: {}".format(M))
                    exit()
        else:
            networkHandling.write_message(conn, networkHandling.RespError("The PoC cannot be verified!"))

    else:
        networkHandling.write_message(conn, networkHandling.RespError("Contribution is not open or has been closed!"))

def HandleTicketRequest(msg, conn, state):
    """Handles the request for getting the ticket. If not existed, return an error.
    
    Arguments:
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """

    #If the ticket has been defined
    if not state.isExpired and state.currentTicket:
        networkHandling.write_message(conn, RespTicket(state.currentTicket, state.currentThreshold, state.currentPubKey))
    else:
        networkHandling.write_message(conn, networkHandling.RespError("The current ticket has not been defined yet!"))

def HandleDecryption(msg, conn, state):
    pass

def HandlePubKeyRequest(msg, conn, state):
    """Handles the request for getting the encryption key from requesters. If not existed, return an error.
    
    Arguments:
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """

    #If the Threshold has been defined
    if state.currentPubKey:
        networkHandling.write_message(conn, RespPubKey(state.currentPubKey))
    else:
        networkHandling.write_message(conn, networkHandling.RespError("The Requester has not connected yet!"))

def HandleThresholdRequest(msg, conn, state):
    """Handles the request for getting the Threshold. If not existed, return an error.
    
    Arguments:
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """

    #If the Threshold has been defined
    if state.currentThreshold:
        networkHandling.write_message(conn, RespThreshold(state.currentThreshold))
    else:
        networkHandling.write_message(conn, networkHandling.RespError("The Threshold has not been defined yet!"))

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
        pubkey = common.CreatePointFromXY(pubkey_X, pubkey_Y)

        nonce = msg['nonce']
        state.currentTicket = common.GenerateTicket(pubkey, nonce)
        state.currentPubKey = pubkey
        print("State", state)
        networkHandling.write_message(conn, RespGenTick(state.currentTicket))
    else:
        networkHandling.write_message(conn, networkHandling.RespError("The current ticket has not been expired yet!"))

class PDLState:
    """
    A model to encapsulate PDL state
    """
    def __init__(self):
        self.currentThreshold = common.ComputeThreshold(config.EXPECTED_NUM_CONTRIBUTORS, 
                                                        config.NUM_PARTIES,
                                                        256)
        self.currentTicket = None
        self.isExpired = True
        self.numParty = 1
        self.numContributor = 0
        self.currentPubKey = None
        self.currentC = None
        self.currentD = None

    def __str__(self):
        return "<PDLState: currentThreshold: {}, currentTicket: {}, isExpired : {}, parties: {}, contributors: {}, pubkey: {}>".format(
            hex(self.currentThreshold), hex(self.currentTicket), self.isExpired,
            self.numParty, self.numContributor, self.currentPubKey)

if __name__ == "__main__":
    KickOff()