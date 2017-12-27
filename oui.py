#!/usr/bin/python

import re

f = open('OUI.hwdb','r')
data = f.read()
f.close()

f = open('OUI2.hwdb','r')
data = data + f.read()
f.close()

def oui(mac):
    mac = ''.join(mac.split(':')).upper()
    #print mac
    for i in range(1,12):
        out = finder(mac[:i*-1])
        if out:
            return out[0]
            break

def finder(st):
    return re.findall(r'{0}.*=(.*)'.format(st),data)

#oui('ab:cd:ef:ab:cd:ef')
