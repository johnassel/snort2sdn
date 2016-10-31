#! /usr/bin/env python

import time

class ban:
    def __init__(self, pFlowid):
        self.flowId=pFlowid        
        self.bannedTime=int(time.time())

    
t=ban(200)

print(t.flowId)
print(t.bannedTime)
