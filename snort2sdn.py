#!/usr/bin/python
import socket
import os, os.path
import alert
import dpkt
import datetime
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
from xml.dom import minidom

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

def createRule(pDst,pSrc):
    #Reference: https://pymotw.com/2/xml/etree/ElementTree/create.html
    
    dst=pDst+"/32"
    src=pSrc+"/32"
    
    namespace="urn:opendaylight:flow:inventory"
    flow = Element('{urn:opendaylight:flow:inventory}flow') #Namespace!
    
    flowName=SubElement(flow, 'flow-name')
    flowName.text='blockping2opfer'

    tableId=SubElement(flow, 'table_id')
    tableId.text='0'

    iD=SubElement(flow, 'id')
    iD.text='200'

    priority=SubElement(flow, 'priority')
    priority.text='0'

    instructions=SubElement(flow, 'instructions')
    instruction=SubElement(instructions, 'instruction')

    order=SubElement(instruction, 'order')
    order.text='0'

    applyActions=SubElement(instruction, 'apply-actions')
    action=SubElement(applyActions, 'action')
    order=SubElement(action, 'order')
    order.text='0'
    dropAction=SubElement(action, 'drop-action')

    match=SubElement(flow, 'match')
    ethernetMatch=SubElement(match, 'ethernet-match')
    ethernetType=SubElement(ethernetMatch, 'ethernet-type')
    type=SubElement(ethernetType, 'type')
    type.text='2048'
    ipv4dst=SubElement(match, 'ipv4-destination')
    ipv4dst.text=dst
    ipv4src=SubElement(match, 'ipv4-source')
    ipv4src.text=src
    
    print "Blocking using",minidom.parseString(tostring(flow, 'utf-8')).toprettyxml(indent="  ", encoding='UTF-8')

    
def removeFromController(pAddr,pId):
    #Reference: https://docs.python.org/2/library/httplib.html
    addr=pAddr
    id=pId
    
def pushToController(pAddr,pFlow):
    #Reference: https://stackoverflow.com/questions/33127636/put-request-to-rest-api-using-python https://docs.python.org/2/library/httplib.html
    addr=pAddr
    flow=pFlow

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
        createRule(ipDst,ipSrc)


snort.close()
os.remove(socketPath)

print "Done. Bye."
