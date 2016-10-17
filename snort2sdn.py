#!/usr/bin/python
import socket
import os, os.path
import alert
import dpkt
import datetime

socketPath="/var/log/snort/snort_alert"

buffersize=alert.AlertPkt._ALERTPKT_SIZE

if os.path.exists(socketPath):
    os.remove(socketPath)
    
#Snort benutzt DGRAM-Sockets, nicht STREAM
snort = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
snort.bind(socketPath)

#setzen des Owners + Group auf Snort (ohne keine alerts)
os.chown(socketPath, 1001, 1001)

def convertMac(addr):#MAC von HEX nach string
    return ':'.join('%02x' % ord(b) for b in addr)

def convertIp(addr):
    return socket.inet_ntop(socket.AF_INET, addr)

def getType(number):
    type = "kA"
    if number == 2048:
        type = "IPv4"
    return type

def createRule(dst,src):
    return null
    #todo https://pymotw.com/2/xml/etree/ElementTree/create.html
    
def removeFromController(addr,id):
    return null
    #todo https://docs.python.org/2/library/httplib.html
    
def pushToController(addr):
    return null
    #todo https://stackoverflow.com/questions/33127636/put-request-to-rest-api-using-python https://docs.python.org/2/library/httplib.html

print("Warten")
while True:
    #Alerts aus dem Socket holen und vorbereiten
    data = snort.recv(buffersize)
	
    parsedAlert=alert.AlertPkt.parser(data)    
    
    
    #Entpacken des Ethernet-Frames: http://dpkt.readthedocs.io/en/latest/api/api_auto.html#dpkt.ethernet.Ethernet.data
    etherFrame=dpkt.ethernet.Ethernet(parsedAlert.pkt)
    
    #Alertmessage
    msg=parsedAlert.alertmsg
    
    #MAC-Adressen
    macSrc = convertMac(etherFrame.src)
    macDst = convertMac(etherFrame.dst)
    
    #IP-Adressen
    ipSrc = convertIp(etherFrame.data.src)
    ipDst = convertIp(etherFrame.data.dst)
    
    #Typ des Packetes
    packetType = etherFrame.type
    
    
    if not data:
        break
    else:
        print "-" * 20
        print str(datetime.datetime.now())
        print "Alert: ", msg[0] #msg ist ein Tupel
        print "MAC-Source: ", macSrc, " MAC-Destination: ", macDst 
        print "IP-Source: ",ipSrc, " IP-Destination: ", ipDst
        print "Type: ", getType(packetType)#Typ nach: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml (2048=IPv4)


snort.close()
os.remove(socketPath)

print "Done. Bye."
