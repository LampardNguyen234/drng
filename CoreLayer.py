import socket
from Party import Party
import PDL_interface
import common
import config
from network_handling import *

def main():
    partyList = list()
    for i in range(config.NUM_PARTIES):
        partyList.append(Party())
    sock_to_PDL = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_to_PDL.connect(config.PDL_ADDR)
    req = PDL_interface.ReqTicket()
    write_message(sock_to_PDL, req)
    resp = read_message(sock_to_PDL)

    if isinstance(resp, RespError):
        print(resp)
    elif resp['__class__'] == 'RespTicket':
        T = resp['__value__']['ticket']
        Th = resp['__value__']['threshold']

        Y = resp['__value__']['pubkey']
        Y = common.parse_point(Y)

        for party in partyList:
            party.kick_off(T, Th, Y)

if __name__ == '__main__':
    main()
    