'''
@author Gonzalo Gasca Meza
        AT&T Labs, Inc
        gg608f[at]att.com
        Date: September 2013
        Purpose: Sniffs all incoming and outgoing SIP packets and upload geoLocation information to parse.com
        February 2014 - Version 1.1 Add SIP CLF support

'''
import socket,sys,logging,traceback,re,urllib,ast,os,binascii,datetime,delorean,string,random,time
#from Queue import Queue #Queue encapsulates the behaviour of Condition, wait(), notify(), acquire() etc.
from twilio.rest import TwilioRestClient
from parse_rest.connection import register
from parse_rest.datatypes import Object,GeoPoint
from threading import Thread
from time import sleep
from struct import *
from collections import defaultdict

#from gevent import monkey, Greenlet, GreenletExit
#monkey.patch_socket()
#from gevent.queue import Queue
#import psutil
#from memory_profiler import profile

sys.excepthook = lambda *args: None
sipTransactions = {}
sipTransactionList = []

# SipTransaction Object
class sipTransaction(Object):
    """Create a SIP Transaction"""
    def __init__(self,callId):
        #print 'sipTransaction() - New sipTransaction() object created()'
        self.callId  = callId
        self.timerT1    = 500
        self.timerA     = self.timerT1
        self.timerB     = 64*self.timerT1
        self.timerD     = 32000
        self.timerH     = 64*self.timerT1

    def setState(self,state):
        self.sipState = state

    def getState(self):
        return self.sipState

    def getSipCallId(self): 
        return self.callId


#@profile
def main():
    print 'Starting Main()....'
    sipTransaction1 = sipTransaction("AAAA-BBBB-CCCC-DDDD")
    sipTransaction2 = sipTransaction("AAAA-BBBB-CCCC-DDDD-EEEEE")
    sipTransaction1.timerA = 10000
    print sipTransaction1.getSipCallId()
    print sipTransaction2.getSipCallId()
    
    sipTransactions[sipTransaction1.getSipCallId()] = 0
    sipTransactions[sipTransaction2.getSipCallId()] = 1
    
    sipTransactionList.append(sipTransaction1)
    sipTransactionList.append(sipTransaction2)
    start = time.time()
    for i in range(1,10000):
        sipTransactionList.append(sipTransaction(i))
    end = time.time()
    elapsed = end - start
    print elapsed
    print "**********"
    value = "AAAA-BBBB-CCCC-DDDD"
    for sipCall in sipTransactionList:
        if sipCall.callId == 500:
            print "Yes!"
            print sipCall.callId
            
    
    print sipTransaction1.getSipCallId() in sipTransactions
    print sipTransactions[sipTransaction1.getSipCallId()]
    #sipStateMachine()
    print 'Finalized()....'
    
if __name__ == '__main__':
    main()