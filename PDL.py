from PDL_interface import *
import socket
import common
import network_handling
import config
from Party_interface import PoC, PoE
from Crypto.Random import random
import Requester_interface

def kick_off():
    """Kicks off the PDL. Creates/binds a socket and starts listening for any requests.
    """
    state = PDLState()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(config.PDL_ADDR)
    sock.listen()

    print("PDL started!!!")

    while True:
        conn, addr = sock.accept()
        msg = network_handling.read_message(conn)
        if not msg:
            conn.close()
            continue
        handle_message(msg, conn, state)
        conn.close()

def handle_message(msg, conn, state):
    """Handles received messages as appropriate
    
    Arguments:\n
        msg -- received message
        conn -- the connection socket
        state -- current state of the PDL
    """

    # print("\nReceived a new message: {} from {}".format(msg, conn.getpeername()))
    if msg['__class__'] == 'ReqGenTick':
        handle_generate_ticket(msg['__value__'], conn, state)
    elif msg['__class__'] == 'ReqThreshold':
        handle_threshold_request(msg['__value__'], conn, state)
    elif msg['__class__'] == 'ReqPubKey':
        handle_pubkey_request(msg['__value__'], conn, state)
    elif msg['__class__'] == 'ReqTicket':
        handle_ticket_request(msg['__value__'], conn, state)
    elif msg['__class__'] == 'ReqContribution':
        handle_contribution(msg['__value__'], conn, state)

def handle_contribution(msg, conn, state):
    """Handles contribution from party.

    Arguments:\n
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """

    #If the Threshold has been defined
    if not state.isExpired:
        pubkey = common.EC_point_from_JSON(msg['pubkey'])
        C = common.EC_point_from_JSON(msg['C'])
        D = common.EC_point_from_JSON(msg['D'])

        print("\nNew contribution received:")
        print("C = {}\nD = {}".format(C, D))

        sigma_r = msg['sigma_r']
        sigma_s = msg['sigma_s']

        pubkey = common.create_pubkey_from_point(pubkey)
        sigma = common.create_signature_from_rs(sigma_r, sigma_s)
        poc = PoC(pubkey, state.currentTicket, C, D, sigma)

        if poc.verify():
            state.numContributor += 1
            if state.currentC is None:
                state.currentC = C
                state.currentD = D
            else:
                state.currentC = state.currentC + C
                state.currentD = state.currentD + D
            network_handling.write_message(conn, RespContribution("Contribution success!"))
            if state.numContributor == state.numParty:
                print("\nContribution complete!")
                print("\nSending tallied result to the Requester!")

                sock_to_req = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_to_req.connect(config.REQUESTER_ADDR)
                req = Requester_interface.ReqDecryption(state.currentC, state.currentD)
                network_handling.write_message(sock_to_req, req)
                
                resp = network_handling.read_message(sock_to_req)
                print("\nReceived a decrypted message from the Requester!")
                resp = resp['__value__']
                
                M = resp['M']
                c = resp['c']
                z = resp['z']
                print("M = {}\nc = {}\nz = {}".format(M, c, z))

                M = common.EC_point_from_JSON(M)

                if common.verify_ZKP(state.currentPubKey, M, state.currentC, state.currentD, c, z):
                    print("\nVerifying the ZKP complete!!")
                    print("\nThe final outcome is:\n{}".format(common.hash(M)))
                    exit()
                else:
                    print("\nVerifying ZKP failed!!!")
        else:
            network_handling.write_message(conn, network_handling.RespError("The PoC cannot be verified!"))

    else:
        network_handling.write_message(conn, network_handling.RespError("Contribution is not open or has been closed!"))

def handle_ticket_request(msg, conn, state):
    """Handles the request for getting the ticket. If not existed, returns an error.
    
    Arguments:\n
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """

    #If the ticket has been defined
    if not state.isExpired and state.currentTicket:
        network_handling.write_message(conn, RespTicket(state.currentTicket, state.currentThreshold, state.currentPubKey))
    else:
        network_handling.write_message(conn, network_handling.RespError("The current ticket has not been defined yet!"))

def handle_pubkey_request(msg, conn, state):
    """Handles the request for getting the encryption key from requesters. If not existed, returns an error.
    
    Arguments:\n
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """

    #If the Threshold has been defined
    if state.currentPubKey:
        network_handling.write_message(conn, RespPubKey(state.currentPubKey))
    else:
        network_handling.write_message(conn, network_handling.RespError("The Requester has not connected yet!"))

def handle_threshold_request(msg, conn, state):
    """Handles the request for getting the Threshold. If not existed, returns an error.
    
    Arguments:\n
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """

    #If the Threshold has been defined
    if state.currentThreshold:
        network_handling.write_message(conn, RespThreshold(state.currentThreshold))
    else:
        network_handling.write_message(conn, network_handling.RespError("The Threshold has not been defined yet!"))

def handle_generate_ticket(msg, conn, state):
    """Handles the request for generating new ticket from the Requester. If existed, returns an error.
    
    Arguments:\n
        msg -- message from the Requester
        conn -- the connection socket
        state -- current state of the PDL
    """
    #If the ticket has not been created or the current one has not been expired
    if state.isExpired:
        state.isExpired = False

        pubkey_X = msg['pubkey_X']
        pubkey_Y = msg['pubkey_Y']
        pubkey = common.create_point_from_XY(pubkey_X, pubkey_Y)

        nonce = msg['nonce']
        print("A new ticket generation request has been received!")
        print("Public Key: {}\nnonce: {}".format(pubkey, nonce))
        state.currentTicket = common.generate_ticket(pubkey, nonce)
        state.currentPubKey = pubkey
        network_handling.write_message(conn, RespGenTick(state.currentTicket))
    else:
        network_handling.write_message(conn, network_handling.RespError("The current ticket has not been expired yet!"))

class PDLState:
    """
    A model to encapsulate PDL state
    """
    def __init__(self):
        self.currentThreshold = common.compute_threshold(config.EXPECTED_NUM_CONTRIBUTORS, 
                                                        config.NUM_PARTIES,
                                                        256)
        self.currentTicket = None
        self.isExpired = True
        self.numParty = 2
        self.numContributor = 0
        self.currentPubKey = None
        self.currentC = None
        self.currentD = None

    def __str__(self):
        return "<PDLState: currentThreshold: {}, currentTicket: {}, isExpired : {}, parties: {}, contributors: {}, pubkey: {}>".format(
            hex(self.currentThreshold), hex(self.currentTicket), self.isExpired,
            self.numParty, self.numContributor, self.currentPubKey)

if __name__ == "__main__":
    kick_off()