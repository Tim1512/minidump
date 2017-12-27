#!/usr/bin/python

import sys

if len(sys.argv) < 3:
    print 'Usage : ./minidump.py interface NumOfPackets'
    sys.exit()

import os,oui
from scapy.all import *

conf.iface = sys.argv[1]
np = int(sys.argv[2])

# initial value to start packet counting
ini = 0

bssids = []
clients = []

# bssids set
bs = set()
# clients set
cs = set()
# probe requests set
ps = set()
# data packect set
ds = set()
# global channel number
ch = 0

# this function is used to hop channels
# you can use your own code to hop channels but the performance is bit low
# this dummy function you can write your logic here
def hopper():
    global ch
    if ch == 12:
        ch = 0
    ch = ch + 1
    #print 'hopping to ' + str(ch)
    #os.system('iwconfig ' + conf.iface + ' channel ' + str(ch) )

# function returning authentication type only for beacon frames
def auth(pkt):
    f = 0
    while pkt.payload and f == 0:

        if pkt.name == '802.11 Information Element':

            # WPA2 checking
            if pkt.ID == 48:
                f = 1
                val = 'WPA2' + '$'
                if pkt.info[2:6] == '\x00\x0f\xac\x04':
                    val = val + 'CCMP' + '$'
                elif pkt.info[2:6] == '\x00\x0f\xac\x02':
                    val = val + 'TKIP' + '$'
                if pkt.info[14:18] == '\x00\x0f\xac\x02':
                    val = val + 'PSK'
                elif pkt.info[14:18] == '\x00\x0f\xac\x01':
                    val = val + 'MGT'

            # WPA and WEP checking
            elif pkt.ID == 221 and pkt.info[0:4] == '\x00P\xf2\x01':
                f = 1

                # WEP checking
                if pkt.info[12:16] == '\x00P\xf2\x04':
                    val = 'WPA' + '$' + 'CCMP' + '$'
                    if pkt.info[18:22] == '\x00P\xf2\x02':
                        val = val + 'PSK'
                    elif pkt.info[18:22] == '\x00P\xf2\x01':
                        val = val + 'MGT'
                elif pkt.info[12:16] == '\x00P\xf2\x02':
                    val = 'WPA' + '$' + 'TKIP' + '$'
                    if pkt.info[18:22] == '\x00P\xf2\x02':
                        val = val + 'PSK'
                    elif pkt.info[18:22] == '\x00P\xf2\x01':
                        val = val + 'MGT'

                # WEP checking
                if pkt.info[12:16] == '\x00P\xf2\x02':
                    val = 'WEP' + '$'
                    if pkt.info[18:22] == '\x00P\xf2\x02':
                        val = val + 'PSK' + '$ '
                    else:
                        val = val + 'OPN' + '$ '

        pkt = pkt.payload
    if f == 0:
        val = 'OPN$ $ '
    return val

def final():
    print chr(27) + "[2J"
    global bssids
    global clients
    print "miniDump "
    print "==============================================================================================================="
    print '{0:30}        {1:15}        {2:2}        {3:4}      {4:4}      {5:3}'.format('BSSID','ESSID','CH','ENC','CIPHER','AUTH')
    for i in bssids:
        print '{0:30}        {1:15}        {2:2}        {3:4}      {4:4}        {5:3}'.format(*i.split('$'))
    print "==============================================================================================================="
    print '{0:30}    {1:30}    {2:30}    {3:2}'.format('CLIENT','BSSID','PROBE/DATA','CH')
    for i in clients:
        print '{0:30}    {1:30}    {2:30}    {3:2}'.format(*i.split('$'))

# callback function to handle all packets
def cb(pkt):
    # checking for 802.11 packets only
    if pkt.haslayer(Dot11):

        # checking for all access points by looking at beacon frames
        if pkt.payload.payload.name == '802.11 Beacon':
            if (pkt.addr2  + pkt.payload.payload.payload.info + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1) not in bs):
                bs.add(pkt.addr2 + pkt.payload.payload.payload.info + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1))
                bssids.append(pkt.addr2 + ' ' + oui.oui(pkt.addr2).split(' ')[0] + '$' + pkt.payload.payload.payload.info + '$' + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1) + '$' + auth(pkt))
                #print pkt.payload.payload.payload.info,auth(pkt)

        # looking for clients by association requests or probe requests or reassociation requests or if to ds is 1 (client to ap) and looking at transmitter address
        elif pkt.payload.payload.name == '802.11 Association Request' or pkt.payload.payload.name == '802.11 Probe Request' or pkt.payload.FCfield == 1L or pkt.payload.payload.name == '802.11 Reassociation Request':

            # checking for probe requests and printing probed ssid
            if pkt.__contains__('Dot11ProbeReq') and (pkt.addr2  + pkt.addr1 + pkt[Dot11ProbeReq].payload.info + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1) not in ps):
                ps.add(pkt.addr2 + pkt.addr1 + pkt[Dot11ProbeReq].payload.info + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1))
                clients.append(pkt.addr2 + ' ' + oui.oui(pkt.addr2).split(' ')[0] +'$' + pkt.addr1 +' ' + oui.oui(pkt.addr1).split(' ')[0] + '$' + pkt[Dot11ProbeReq].payload.info + '$' + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1) )

            # printing if packet is data packet or not
            if pkt.payload.type == 2L and (pkt.addr2 + pkt.addr1 + 'data' +str(((ord(pkt.notdecoded[18])) - 108)/5 + 1)  not in ds):
                ds.add(pkt.addr2 + pkt.addr1 + 'data' + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1))
                clients.append(pkt.addr2 + ' ' + oui.oui(pkt.addr2).split(' ')[0] + '$' + pkt.addr1 + ' ' + oui.oui(pkt.addr1).split(' ')[0] + '$' + 'data' + '$' + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1))

            # showing if device is associating or resassociating
            if ( pkt.payload.payload.name == '802.11 Association Request' or pkt.payload.payload.name == '802.11 Reassociation Request' ) and (pkt.addr2 + pkt.addr1 + pkt.payload.payload.name + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1)  not in cs):
                cs.add(pkt.addr2  + pkt.addr1 + pkt.payload.payload.name + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1))
                clients.append(pkt.addr2 + ' ' +  oui.oui(pkt.addr2).split(' ')[0] + '$' + pkt.addr1 + ' ' + oui.oui(pkt.addr1).split(' ')[0] + '$' + pkt.payload.payload.name + '$' + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1))

	# looking for clients by association response or probe response or re-association response and if from ds = 1 (ap to client ) by looking at reciever address
        elif  pkt.payload.FCfield == 2L :

            # printing if packet is data packet or not
            if pkt.payload.type == 2L and (pkt.addr1 + pkt.addr2 + 'data' +str(((ord(pkt.notdecoded[18])) - 108)/5 + 1)  not in ds):
                ds.add(pkt.addr1 + pkt.addr2 + 'data' + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1))
                clients.append(pkt.addr1 + ' ' + oui.oui(pkt.addr1).split(' ')[0] + '$' + pkt.addr2 + ' ' + oui.oui(pkt.addr2).split(' ')[0] + '$' + 'data' + '$' + str(((ord(pkt.notdecoded[18])) - 108)/5 + 1))


    global ini
    ini = ini + 1
    # hopping the channels after capturing 20 packets
    #if ini%20 == 0:
    #    hopper()
    # printing the screen after capturing 50 packets
    if ini%50 == 0:
        final()

try:
    print chr(27) + "[2J"
    sniff(count=np,prn=cb)
except KeyboardInterrupt:
    sys.exit()
