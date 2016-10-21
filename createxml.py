#!/usr/bin/python
from xml.etree.ElementTree import Element, SubElement, Comment, tostring, register_namespace
from xml.dom import minidom

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
ipv4dst.text='192.168.30.6/32'
ipv4src=SubElement(match, 'ipv4-source')
ipv4src.text='192.168.50.40/32'

register_namespace('', "urn:opendaylight:flow:inventory")

print minidom.parseString(tostring(flow, 'utf-8')).toprettyxml(indent="  ", encoding='UTF-8')
