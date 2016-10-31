#! /usr/bin/env python

import socket

s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.connect('/var/log/snort/snort_alert')

s.send('Test message.')
s.close()
