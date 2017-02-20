#!/usr/bin/python
import socket
import os, os.path
import alert
import dpkt
import datetime
import time
import requests
from xml.etree.ElementTree import Element, SubElement, Comment, tostring, register_namespace
from xml.dom import minidom
from subprocess import call
from thread import start_new_thread

##Beginn Konfiguration##

switchId="openflow:178256403006279"
controllerAddr="http://controller:8181/restconf/config/opendaylight-inventory:nodes/node/"+switchId+"/flow-node-inventory:table/0/flow/"
controllerUser="admin"
controllerPass="admin"
ruleCounter=200 #Start-ID des Flows, ab welchem Bann-Eintraege abgelegt werden
banTime=120 #Zeit fuer Bann in Sekunden
socketPath="/var/log/snort/snort_alert"
##Ende Konfiguration##
##Vorbereitung##
buffersize=alert.AlertPkt._ALERTPKT_SIZE
bans=[] #Liste mit REST-IDs der im Controller gebannten IPs - Anfange: alte Eintraege, Ende: neue Eintraege

if os.path.exists(socketPath): #Erstellung des Sockets
    os.remove(socketPath)
    
#Snort benutzt DGRAM-Sockets, nicht STREAM
snort = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
snort.bind(socketPath)
#setzen des Owners + Group auf Snort (ohne keine alerts)
os.chown(socketPath, 1001, 1001)
call(["systemctl", "restart", "snortd"]) #Neustart von Snort, damit Socket genutzt wird

class banDetails: #Speichert ID mit zugehoeriger Zeit, ab wann der Bann abgelaufen ist
    def __init__(self, pFlowid):
        self.flowId=pFlowid        
        self.bannedTime=int(time.time()) #Unix-Zeitstempel
        print "BanID: ",self.flowId," banned time: ",self.bannedTime

def checkExpired(): #Pruefung, ob Eintraege abgelaufen sind
    global bans
    global banTime
    
    while True:
        currentTime=int(time.time())
        time.sleep(1) #verhinder hohe CPU-Last
        if len(bans)>0:
            counter=0
            for ban in bans:
                if ban.bannedTime+banTime<=currentTime:
                    print "Removing ",ban.flowId," with banned time ",ban.bannedTime," current time ",currentTime
                    removeFromController(bans.pop(counter).flowId)
                counter=counter+1
    

def convertMac(addr):#MAC von HEX nach string
    return ':'.join('%02x' % ord(b) for b in addr)

def convertIp(addr):
    return socket.inet_ntop(socket.AF_INET, addr)

def getType(number):
    type = "kA"
    if number == 2048:
        type = "IPv4"
    return type

def createRule(pDst,pSrc): #Erstellen des an den Controller zu sendenden XMLs
    #Referenz: https://pymotw.com/2/xml/etree/ElementTree/create.html
   
    dst=pDst+"/32"
    src=pSrc+"/32"

    print "Creating Rule for blocking traffic from "+src+" to "+dst
    
    register_namespace('', "urn:opendaylight:flow:inventory")
    flow = Element('{urn:opendaylight:flow:inventory}flow') #Namespace! Ohne wird der Flow von OpenDaylight nicht angenommen
    
    flowName=SubElement(flow, 'flow-name')
    flowName.text='generated from snort alert'

    tableId=SubElement(flow, 'table_id')
    tableId.text='0'

    iD=SubElement(flow, 'id')
    iD.text=str(ruleCounter)

    priority=SubElement(flow, 'priority')
    priority.text='1000'

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
    
    return tostring(flow, 'utf-8')
    
def removeFromController(pId): #Loeschen eines Flows aus dem Controller
    #Referenz: https://docs.python.org/2/library/httplib.html
    #curl -u admin:admin -X DELETE http://controller:8181/restconf/config/opendaylight-inventory:nodes/node/$switch/flow-node-inventory:table/0/flow/$cur
    id=pId
    addr=controllerAddr+str(id)
    requests.delete(addr, auth=(controllerUser, controllerPass))
    
def pushToController(pFlow): #Senden eines Flows zum Controller
    #Referenz: https://stackoverflow.com/questions/33127636/put-request-to-rest-api-using-python https://docs.python.org/2/library/httplib.html
    #curl -u admin:admin -X PUT -H "Content-Type:application/xml" -H "Accept:application/xml" -d "@block_example.xml" http://controller:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:248752488641088/flow-node-inventory:table/0/flow/200
    global ruleCounter #verhindert Anlegen einer neuen, lokalen Variabel
    global bans    
    flow=pFlow
    addr=controllerAddr+str(ruleCounter)
    headers = {"Content-Type":"application/xml","Accept":"application/xml"}    
    #print "Blocking using",minidom.parseString(flow).toprettyxml(indent="  ", encoding='UTF-8')
    requests.put(addr, auth=(controllerUser, controllerPass), data=flow, headers=headers)    
    bans.append(banDetails(ruleCounter)) #Bann ans Ende der List setzen   
    ruleCounter=ruleCounter+1    

#####Beginn der Programmlogik#####

start_new_thread(checkExpired,()) #Ueberpruefung nach ausgelaufenen Eintraegen in einen eigenen Thread

while True:
    print("waiting")
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
    #Typ des Paketes
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
        pushToController(createRule(ipDst,ipSrc))
        pushToController(createRule(ipSrc,ipDst))

snort.close()
os.remove(socketPath)

print "Done. Bye."
