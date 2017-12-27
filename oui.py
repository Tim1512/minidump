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

#oui('18:a6:f7:14:25:d9')
#oui('00:71:cc:06:68:2d')
#oui('b8:2a:72:9e:43:ad')
