'''
@author Gonzalo Gasca Meza
        AT&T Labs, Inc
        gg608f[at]att.com
        Date: September 2013
        Purpose: Sniffs all incoming and outgoing SIP packets and upload geoLocation information to parse.com
        February 2014 - Version 1.1 Add SIP CLF support

'''
import sipLocatorConfig
import socket,sys,logging,traceback,re,urllib,ast,os,binascii,datetime,delorean,string,random
from twilio.rest import TwilioRestClient
from parse_rest.connection import register
from parse_rest.datatypes import Object,GeoPoint
from threading import Thread
from time import sleep
from logging.handlers import RotatingFileHandler
from struct import *
#from Queue import Queue #Queue encapsulates the behaviour of Condition, wait(), notify(), acquire() etc.
#from gevent import monkey, Greenlet, GreenletExit
#monkey.patch_socket()
#from gevent.queue import Queue
#import psutil
#from memory_profiler import profile

sys.excepthook = lambda *args: None

# Global variables
register(sipLocatorConfig.PARSE_APPLICATION_ID, sipLocatorConfig.PARSE_REST_API_KEY)
sipClfLog = logging.getLogger('sipClf.core')
sipMessagesList     = []
sipCallListNumber   = []
sipTransactionsList = []
sipTransactions     = {}
sipClfCalls         = {}
sipProcessedCalls   = {}


# SipTransaction Object
class sipTransaction(Object):
    """Create a SIP Transaction"""
    def __init__(self,callId):
        logging.info("sipTransaction() - New sipTransaction object created()")
        print 'sipTransaction() - New sipTransaction() object created()'
        self.callId     = callId
        self.state      = 0
        self.timerT1    = 500
        self.timerA     = self.timerT1
        self.timerB     = 64*self.timerT1
        self.timerD     = 32000
        self.timerH     = 64*self.timerT1

    def setState(self,state):
        self.state = state

    def getState(self):
        return self.state

    def getSipCallId(self): 
        return self.callId


# SipMessage Object using CLF format
class sipClf(Object):
    """Create a SIP CLF Object"""
    def __init__(self):
        logging.info("sipClf() - New sipClf object created()")
        print 'sipClf() - New sipClf object created()'
        # SIP CLF RFC 6872 http://tools.ietf.org/html/rfc6872#section-9
        self.timeStamp = ''         # Epoch time
        self.msgType = ''           # R: Request, r: response
        self.retransmissions = ''   # O: Original Transmission D: Duplicate Transmission S: Server is stateless
        self.directionality = ''    # s: message sent, r: message received        
        self.transport = ''         # tcp, udp, tls
        self.encrypted = ''         # E: Encrypted message, U: Unencrypted message
        self.csqNumber = ''         # Cseq Number
        self.csqMethod = ''         # Cseq: 
        self.reqUri = ''            # SIP URI
        self.dstAddress = ''        # IP Address destination
        self.dstPort = ''           # Transport Destination port
        self.srcAddress = ''        # IP address source
        self.srcPort = ''           # Transport Source port
        self.toUri = ''             # The To URI. For the sake of brevity, URI parameters should not be logged
        self.toTag = ''             # The tag parameter of the To header
        self.fromUri = ''           # The From URI.  For the sake of brevity, URI parameters should not be logged
        self.fromTag = ''           # The tag parameter of the From header
        self.callId = ''            # Call Id
        self.status = ''            # SIP status code if available
        self.serverTxn = ''         # Server transaction identification code - UAS
        self.clientTxn = ''         # Client transaction identification code - UAC
        # SIP Header and SDP information
        self.sipMsgIpInfo = ''      # Store IP information
        self.sipHeaderInfo    = {}  # Store SIP Header Info
        self.sipMsgSdpInfo    = {}  # Store SIP SDP contents
        self.sipMsgMethodInfo = ''  # Store SIP Mthod info
        self.containsError    = False

    def processSipMsgTimeStamp(self):
        dt = datetime.datetime.utcnow()
        self.timeStamp = delorean.Delorean(dt, timezone="UTC").epoch()

    def processSipMsgType(self):
        Message = re.search(r'(\w+\s+sip:.*)|(^SIP/2.0\s.*)', self.sipMsgMethodInfo)
        #Request
        if Message.group(1):
            # Find Method Name or SIP Response
            self.msgType = 'R'
        #Response
        elif Message.group(2):
            message = Message.group(2)
            self.msgType = 'r'
        else:
            self.msgType = '?'
            logging.error('processSipMsgType() - Unknow message Type')
            self.containsError = True

    def processSipMsgRetransmission(self):
        #TODO Add Retransmission support in Transport Layer TCP|UDP
        self.retransmissions = 'S'

    def processSipMsgIpInfo(self):
        if self.sipMsgIpInfo!='' or self.sipMsgIpInfo == None:
            self.srcAddress = self.sipMsgIpInfo.get('s_addr') if validIpAddress(self.sipMsgIpInfo.get('s_addr')) else '?' 
            self.dstAddress = self.sipMsgIpInfo.get('d_addr') if validIpAddress(self.sipMsgIpInfo.get('d_addr')) else '?'
            self.srcPort    = self.sipMsgIpInfo.get('source_port') if validTcpPort(self.sipMsgIpInfo.get('source_port')) else '?'
            self.dstPort    = self.sipMsgIpInfo.get('dest_port') if validTcpPort(self.sipMsgIpInfo.get('dest_port')) else '?'
        else:
            logging.error('processSipMsgIpInfo() - No ip address defined')
            self.containsError = True

    def processSipMsgTransport(self):
        if self.sipMsgIpInfo!='' or self.sipMsgIpInfo == None:
            if self.sipMsgIpInfo.get('protocol')==6:
                if sipLocatorConfig.ENABLE_TLS:
                    self.transport='T'
                    self.encrypted='E'
                else:    
                    self.transport='T'
                    self.encrypted='U'
            elif self.sipMsgIpInfo.get('protocol')==17:
                self.transport='U'
                self.encrypted='U'
            else:
                self.transport = '?'
                self.encrypted='?'
        else:
            logging.error('processSipMsgTransport() No ip address defined')
            self.containsError = True
            self.transport = '?'
            self.encrypted='?'

    def processSipMsgDirection(self):
        #s: message sent, r: message received
        try:
            if self.sipMsgIpInfo!='' or self.sipMsgIpInfo == None:
                #Extract Network Card information and do not include loopback IP address
                ip_address = ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1])
                #Single Network Interface
                if len(ip_address) == 1:
                    if ip_address[0] == self.srcAddress and validIpAddress(ip_address[0]):
                        self.directionality = 's'                        
                    elif ip_address[0] == self.dstAddress and validIpAddress(ip_address[0]):
                        self.directionality = 'r'
                    else:
                        self.directionality = '?'
                        logging.error('processSipMsgDirection() - Unknown directionality Interface: ' + ip_address[0] + ' - srcAddress: ' + self.srcAddress + ' - dstAddress: ' + self.dstAddress)
                        self.containsError = True
                #Multiple Network interfaces. Verify Local Private IP Address Parameter in Configuration File
                else:   
                    if self.srcAddress == sipLocatorConfig.SIP_PRIVATE_HOSTNAME and validIpAddress(sipLocatorConfig.SIP_PRIVATE_HOSTNAME):
                        self.directionality = 's'
                    else:
                        self.directionality = 'r'
            else:
                logging.error('processSipMsgDirection() No ip address defined')
                self.containsError = True
                self.directionality = '?'
        except Exception,e:
            logging.error('processSipMsgDirection() - Exception  - ' + str(e))
            self.directionality = '?'
            self.containsError = True
            print traceback.format_exc()
            print e

    def processSipMsgFromTag(self):
        try:
            header = self.sipHeaderInfo['From:']
            if header !='' and header!=None:
                fromTagRegex = r".*;tag=(.*)"
                Message = re.search(fromTagRegex,header)
                if Message.group(1):
                    self.fromTag = Message.group(1)
                else:
                    print "processSipMsgFromTag() - No From Tag Found"
                    self.fromTag = '-'
            else:
                print "processSipMsgFromTag() - No From Header Found"
                self.fromTag = '?'
                self.containsError = True
        except Exception,e:
            logging.error('processSipMsgFromTag() - Exception - '  + str(e))
            self.fromTag = '?'
            self.containsError = True
            print traceback.format_exc()
            print e
            
    def processSipMsgFromUri(self):
        try:
            header = self.sipHeaderInfo['From:']
            if header !='' and header!=None:
                fromUriRegex = r".*<(sip:.*)>.*"
                Message = re.search(fromUriRegex,header)
                if Message.group(1):
                    self.fromUri = Message.group(1)
                else:
                    print "processSipMsgFromUri() - No From Uri Found"
                    self.fromUri = '?'
                    self.containsError = True
            else:
                print "processSipMsgFromUri() - No From Uri Found"
                self.fromUri = '?'
                self.containsError = True
        except Exception,e:
            self.fromUri = '?'
            self.containsError = True
            print traceback.format_exc()
            print e

    def processSipMsgToTag(self):
        try:
            header = self.sipHeaderInfo['To:']
            if header !='' and header!=None:
                toTagRegex = r".*;tag=(.*)"
                Message = re.search(toTagRegex,header)
                if Message:
                    self.toTag = Message.group(1)
                else:
                    self.toTag = '-'
                    #logging.warn('No toTag found')
            else:
                print "processSipMsgToTag() - No To Header Found"
                logging.error("processSipMsgToTag() - No To Header Found")
                self.toTag = '?'
                self.containsError = True
        except Exception,e:
            self.containsError = True
            print traceback.format_exc()
            print e

    def processSipMsgToUri(self):
        try:
            header = self.sipHeaderInfo['To:']
            if header !='' and header!=None:
                toUriRegex = r".*<(sip:.*)>.*"
                Message = re.search(toUriRegex,header)
                if Message.group(1):
                    self.toUri = Message.group(1)
                else:
                    print "processSipMsgToUri() - No To URI"
                    self.toUri = '?'
                    self.containsError = True
            else:
                print "processSipMsgToUri() - No To Header Found"
                self.toUri = '?'
                self.containsError = True
        except Exception,e:
            self.toUri = '?'
            self.containsError = True
            print traceback.format_exc()
            print e

    def processSipMsgCallId(self):
        try:
            self.callId = self.sipHeaderInfo['Call-ID:']
        except KeyError:
            print 'processSipMsgCallId() No Key: "Call-ID:"'
            self.callId = '?'
            self.containsError = True
        except Exception,e:
            self.callId = '?'
            self.containsError = True
            print traceback.format_exc()
            print e

    def processSipMsgCSeq(self):
        try:
            Cseq = self.sipHeaderInfo['CSeq:']
            if Cseq !='' and Cseq!=None:  
                CSeqRegex = r"\s?(\d+)\s(\w+).*"
                Message = re.search(CSeqRegex,Cseq)
                if Message.group(1):
                    self.csqNumber = Message.group(1)
                    if Message.group(2):
                        self.csqMethod = Message.group(2)
                    else:
                        self.csqMethod = '?'
                        self.containsError = True
                else:
                    print "processSipMsgCSeq() - No CSeq"
                    self.csqNumber = '?'
                    self.csqMethod = '?'
                    self.containsError = True
            else:
                print "processSipMsgCSeq() - No Cseq Header Found"
                self.csqNumber = '?'
                self.csqMethod = '?'
                self.containsError = True
        except KeyError:
            print 'processSipMsgCSeq() = No Key: "CSeq"'
            self.csqNumber = '?'
            self.csqMethod = '?'
            self.containsError = True
        except Exception,e:
            self.csqNumber = '?'
            self.csqMethod = '?'
            self.containsError = True
            print traceback.format_exc()
            print e
    
    def processSipMsgReqUri(self):
        #sip:test@video.att.com
        #sip:1.1.1.1
        #sip:test@video.att.com:5060
        try:
            sipLine = self.getSipMsgMethod()
            Message = re.search(r'\w+\s+(sip:.*)\sSIP/2.0.*|\w+\s+(sip:.*\@.*:\d+).*|\w+\s+(sip:.*\@.*)\sSIP/2.0.*', sipLine)
            if Message:
                self.reqUri = Message.group(1)
            else:
                self.reqUri = '-'
        except Exception,e:
            self.reqUri = '?'
            self.containsError = True
            print traceback.format_exc()
            print e
      
    def processSipMsgStatusCode(self):
        try:
            sipLine = self.getSipMsgMethod()
            Message = re.search(r'(\w+\s+sip:.*)|(^SIP/2.0\s.*)', sipLine)
            if Message:
                codeRegex  = r"^SIP/2.0\s(\d{3})\s(.*)"
                statusLine = re.search(codeRegex,Message.group(0))
                if statusLine:
                    #logging.info("processSipMsgStatusCode() Status Code: " + statusLine.group(1) + ' Method: ' + statusLine.group(2))
                    self.status = statusLine.group(1)
                else:
                    self.status = '-'
            else:
                self.status = '-'
        except Exception,e:
            self.status = '?'
            self.containsError = True
            print traceback.format_exc()
            print e

    def processSipMsgTransaction(self):
        #Verify if B2BUA is enabled
        try:
            if sipLocatorConfig.SIP_CLF_MODE_CLIENT:
                #Check call is in system cached in order to determine if its originated locally or not            
                if self.callId in sipProcessedCalls.keys() and self.callId in sipClfCalls.keys():
                    logging.info('sipClf() - processSipMsgTransaction - Call exists in system Call-ID: %s Local: (%s), Code: (%s)', self.callId,str(sipProcessedCalls.get(self.callId)),sipClfCalls.get(self.callId))
                    if sipProcessedCalls.get(self.callId) == True: #Local Call originated as client
                        self.clientTxn = sipClfCalls.get(self.callId)
                        self.serverTxn = '-'
                        logging.info('sipClf() - processSipMsgTransaction - Message: %s Call-ID: %s (%s) clientTxn:(%s)',self.sipMsgMethodInfo, self.sipHeaderInfo['Call-ID:'], self.sipMsgIpInfo.get('s_addr'),self.clientTxn)
                    else:
                        self.serverTxn = sipClfCalls.get(self.callId)
                        self.clientTxn = '-'
                        logging.info('sipClf() - processSipMsgTransaction - Message: %s Call-ID: %s (%s) serverTxn:(%s)',self.sipMsgMethodInfo, self.sipHeaderInfo['Call-ID:'], self.sipMsgIpInfo.get('s_addr'),self.serverTxn)
                elif not self.callId in sipProcessedCalls.keys():                    
                    # TODO: Add REGISTER Support
                    logging.warn('sipClf() - processSipMsgTransaction() - SIP Message not in cache Call-ID: %s',self.sipHeaderInfo['Call-ID:'])
                    self.serverTxn = '-'
                    self.clientTxn = '-'
            else:
                #TODO
                logging.info('sipClf() - processSipMsgTransaction - B2BUA Disabled')
        except Exception,e:
            self.serverTxn = '?'         # Server transaction identification code - UAS
            self.clientTxn = '?'         # Client transaction identification code - UAC
            self.containsError = True
            logging.info('sipClf() - processSipMsgTransaction() - Exception - ' + str(e))
            print traceback.format_exc()
            print e

    def processSipMsgClf(self):
        self.processSipMsgTimeStamp()
        self.processSipMsgType()
        self.processSipMsgRetransmission()
        self.processSipMsgIpInfo()
        self.processSipMsgTransport()
        self.processSipMsgDirection()
        self.processSipMsgFromTag()
        self.processSipMsgFromUri()
        self.processSipMsgToTag()
        self.processSipMsgToUri()
        self.processSipMsgCallId()
        self.processSipMsgCSeq()
        self.processSipMsgReqUri()
        self.processSipMsgStatusCode()
        self.processSipMsgTransaction()

    def printSipMsgClf(self,advancedMode):
        logging.info("------------------------------------------------------printSipMsgClf() App Processing SIP CLF message------------------------------------------------------")
        logging.info('printSipMsgClf - Timestamp: ' + str(self.timeStamp))
        logging.info('printSipMsgClf - Message Type: ' + self.msgType)
        logging.info('printSipMsgClf - Directionality: ' + self.directionality)
        logging.info('printSipMsgClf - Retransmission: ' + self.retransmissions)
        logging.info('printSipMsgClf - Transport: ' + str(self.transport))
        logging.info('printSipMsgClf - Encrypted: ' + str(self.encrypted))
        logging.info('printSipMsgClf - CSeq-Number: ' + self.csqNumber)
        logging.info('printSipMsgClf - CSeq-Method: ' + self.csqMethod)
        logging.info('printSipMsgClf - R-URI: ' + self.reqUri)
        logging.info('printSipMsgClf - Destination-address: ' + self.dstAddress)
        logging.info('printSipMsgClf - Destination-port: ' + str(self.dstPort))
        logging.info('printSipMsgClf - Source-address: ' + self.srcAddress)
        logging.info('printSipMsgClf - Source-port: ' + str(self.srcPort))
        logging.info('printSipMsgClf - To: ' + self.toUri)
        logging.info('printSipMsgClf - To tag: ' + self.toTag)
        logging.info('printSipMsgClf - From: ' + self.fromUri)
        logging.info('printSipMsgClf - From tag: ' + self.fromTag)
        logging.info('printSipMsgClf - Call-ID: ' + self.callId)
        logging.info('printSipMsgClf - Status: ' + self.status)
        logging.info('printSipMsgClf - Server-Txn: ' + self.serverTxn)
        logging.info('printSipMsgClf - Client-Txn: ' + self.clientTxn)
        if advancedMode:
            try:
                thread = Thread(target=self.createSipClfRecord,args = ( ))
                thread.daemon = True
                thread.start()
        #       thread.join()
            except Exception,e:
                logging.error("sipClf() - Exception calling createSipClfRecord()" + str(e))
                print traceback.format_exc()
                print e

    # Create SIP CLF Record
    def createSipClfRecord(self):
        sipClfLog.debug(str(self.timeStamp) + ' ' + self.msgType.upper() + self.retransmissions.upper() + self.directionality.upper() + str(self.transport).upper() + str(self.encrypted).upper() + ' ' +
            self.csqNumber + ' ' + self.csqMethod + ' ' + self.reqUri + ' ' + self.dstAddress + ' ' + str(self.dstPort) + ' ' + 
            self.srcAddress + ' '  + str(self.srcPort) + ' ' + self.toUri + ' ' + self.toTag + ' ' + self.fromUri + ' ' + 
            self.fromTag + ' ' + self.callId + ' ' + self.status + ' ' + self.serverTxn + ' ' + self.clientTxn)

    def addSipHeader(self,header,value):      
        self.sipHeaderInfo.update({header: value})

    def addSdpInfo(self,sdpLineNumber,sdpKey,sdpValue):      
        #self.sipMsgSdpInfo.update({sdpKey: sdpValue})
        #self.sipMsgSdpInfo.append(sdpKey + '=' + sdpValue)
        sdpLine = sdpKey + '=' + sdpValue
        self.sipMsgSdpInfo.update({sdpLineNumber: sdpLine})

    def getSipHeaders(self):
        return self.sipHeaderInfo

    def setSipMsgTimeStamp(self,timeStamp):
        self.timeStamp = timeStamp

    def getSipMsgTimeStamp(self):
        return self.timeStamp

    def setSipMsgIpInfo(self,ipInfo):
        self.sipMsgIpInfo = ipInfo

    def getSipMsgIpInfo(self):
        return self.sipMsgIpInfo

    def setSipMsgTransport(self,transport):
        self.transport = transport

    def getSipMsgTransport(self):
        return self.transport

    def setSipMsgType(self,msgType):
        self.msgType = msgType

    def getSipMsgType(self):
        return self.msgType

    def setSipMessage(self,msg):
        self.sipMsgMethodInfo = msg
  
    def getSipMsgMethod(self):
        return self.sipMsgMethodInfo
    
# SipCall Object
class sipCall(Object):
    """Create a SIP Call Object"""
    def __init__(self):
        logging.info("sipCall() - New sipCall object created()")
        print 'sipCall() - New sipCall object created()'
        self.sipCallID = ''
        self.sipCallGeoPoint = GeoPoint(latitude=0.0, longitude=0.0)
        self.sipCallGeoLocation = {}     
        self.localCall   = False
    
    def isLocal(self):
        return self.localCall

    def setLocalCall(self,local):
        self.localCall=local

    def setCallId(self,msg):
        self.sipCallID = msg
 
    def getSipCallId(self): 
        return self.sipCallID

    def setSipCallGeolocation(self,geoLocation):
        self.sipCallGeoLocation = geoLocation

    def getSipCallGeoLocation(self):
        return self.sipCallGeoLocation

    def setSipCallGeoPoint(self,latitudeParam,longitudeParam):
        self.sipCallGeoPoint = GeoPoint(latitude=latitudeParam, longitude=longitudeParam)
     
    def getSipCallGeoPoint(self):
        return self.sipCallGeoPoint    
    
# SipMessage Object
class sipMessage(Object):
    """Create a SIP Message Object"""
    def __init__(self):
        logging.info("sipMessage() - New sipMessage object created()")
        print 'sipMessage() - New sipMessage object created()'
        self.sipHeaderInfo    = {}
        self.sipMsgSdpInfo    = {}
        self.hasSDP           = False
        self.sipMsgMethodInfo = ''
        self.sipMsgCallId     = ''

    def isSipMsgLocal(self):
        try:
            if self.sipMsgIpInfo!='' or self.sipMsgIpInfo == None:
                #Extract Network Card information and do not include loopback IP address
                ip_address = ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1])
                #Single Network Interface
                if len(ip_address) == 1:
                    if ip_address[0] == self.sipMsgIpInfo.get('s_addr') and validIpAddress(ip_address[0]):
                        return True                       
                    elif ip_address[0] == self.sipMsgIpInfo.get('d_addr') and validIpAddress(ip_address[0]):
                        return False
                    else:
                        return False
                #Multiple Network interfaces. Verify Local Private IP Address Parameter in Configuration File
                else:   
                    if self.sipMsgIpInfo.get('s_addr') == sipLocatorConfig.SIP_PRIVATE_HOSTNAME and validIpAddress(sipLocatorConfig.SIP_PRIVATE_HOSTNAME):
                        return True
                    else:
                        return False
            else:
                return False
        except Exception,e:
            logging.error('isSipMsgLocal() - Exception - ' + str(e))
            return False
            print traceback.format_exc()
            print e

    def setSipMessage(self,msg):
        self.sipMsgMethodInfo = msg
  
    def getSipMsgMethod(self):
        return self.sipMsgMethodInfo

    def addSipHeader(self,header,value):      
        self.sipHeaderInfo.update({header: value})
        #logging.info(header + ' ' + value)
        #print 'sipMessage() addHeader ' + 'Header: ' + header + ' Value: ' + value

    def addSdpInfo(self,sdpLineNumber,sdpKey,sdpValue):      
        #self.sipMsgSdpInfo.update({sdpKey: sdpValue})
        #self.sipMsgSdpInfo.append(sdpKey + '=' + sdpValue)
        sdpLine = sdpKey + '=' + sdpValue
        self.sipMsgSdpInfo.update({sdpLineNumber: sdpLine})
        #logging.info(sdpKey + '=' + sdpValue)

    def getSipHeaders(self):
        return self.sipHeaderInfo

    def getSdpInfo(self):
        return self.sipMsgSdpInfo

    def processSipMsgCallId(self):
        self.sipMsgCallId = self.getSipMsgCallId()

    def setSipMsgCallId(self,sipMsgCallIdParam):
        if len(sipMsgCallIdParam)!=0:
            self.setSipMsgCallId = sipMsgCallIdParam  
        else:
            self.setSipMsgCallId = self.getSipMsgCallId()

    def getSipMsgCallId(self):
        try:
            callInfo = self.sipHeaderInfo['Call-ID:']
            #logging.info('getSipMsgCallId() Sip Call-ID: ' + callInfo.get('Call-ID:'))
            return callInfo
        except KeyError:
            print 'getSipMsgCallId() - No Key: "Call-ID"'
        except Exception,e:
            print traceback.format_exc()
    
    def setSipMsgIpInfo(self,ipInfo):
        self.sipMsgIpInfo = ipInfo

    def getSipMsgIpInfo(self):
        return self.sipMsgIpInfo
    
    def processSipMsgSdp(self):
        try:
            sipMsgContainsMedia = self.sipHeaderInfo['Content-Type:']
            if sipMsgContainsMedia is not None:
                if sipMsgContainsMedia.find('application/sdp')!=-1:
                    self.hasSDP = True
            else:
                # No SDP  
                self.hasSDP = False
        # Not all SIP Message contain SDP nor Content-Type        
        except KeyError:    
            pass    
        except Exception,e:
            logging.error("processSipMsgSdp() - Unable to process processSipMsgSdp()")
            print traceback.format_exc()
            print e


#Generate Random code
def generateIdCode(size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for x in range(size))

#Obtain geoLocation
def processGeoLocation(srcIP):
    logging.info("processGeoLocation() - Processing GeoLocation for: " + srcIP)
    try:
        if srcIP!="":
            response = urllib.urlopen('http://freegeoip.net/json/' + srcIP ).read()
            geoLocationInfo = response.splitlines()
            # Obtain Dictionary
            finalGeoLocationPoint  = ast.literal_eval(geoLocationInfo[0])
            logging.info('processGeoLocation() - ' + str(finalGeoLocationPoint))
            return finalGeoLocationPoint
        else:
            logging.error('processGeoLocation() - Error')
    except Exception,e:
        print traceback.format_exc()
        logging.error('processGeoLocation() - Exception - ' + str(e))


# Obtain Message Status
def findSipMsgStatus(sipMethod):
    try:
        Message = re.search(r'(\w+\s+sip:.*)|(^SIP/2.0\s.*)', sipMethod)
        if Message:
            codeRegex  = r"^SIP/2.0\s(\d{3})\s(.*)"
            statusLine = re.search(codeRegex,Message.group(0))
            if statusLine:
                return statusLine.group(1)
            else:
                return None
        else:
            return -1
    except Exception,e:
        return None
        print traceback.format_exc()
        print e


# SIP State Machine implementation
def sipStateMachine(sipMsg):
    timerT1 = 500
    timerA  = timerT1
    timerB  = 64*timerT1
    timerD  = 32000
    timerH  = 64*timerT1

    sipState = enum(INVALID=-1, INIT=0, CALLING=1, PROCEEDING=2, COMPLETED=3, TERMINATED=4 )
    sipCallId  = sipMsg.getSipCallId()
    sipMessage = sipMsg.getSipMsgMethod()

    # Verify sipCallId|sipMessage is valid
    if sipCallId == None or sipMessage == None:
        return None

    # Create New transaction, to determine current state of the SIP Call and launch a new thread
    if not(sipCallId in sipTransactions[sipCallID]):     # SipTransaction has not been processed.               
        # Create new transaction in the System
        sipMsgTransaction = sipTransaction(sipCallID)

        # Initial INVITE or RE-INVITE
        if sipMessage.find('INVITE')!= -1:            
            # Initialize timers
            sipMsgTransaction.timerT1 = timerT1
            sipMsgTransaction.timerA = timerT1
            sipMsgTransaction.timerB = 64*timerT1

            # Add SIP Transactions to list
            sipTransactions[sipCallId] = sipState.CALLING
            sipTransactionsList.append(sipMsgTransaction)

        elif sipMessage.find('REGISTER')!= -1:
            sipTransactions[sipCallId] = sipState.CALLING
            sipTransactionsList.append(sipMsgTransaction)
        else:
            logging.error('sipStateMachine Invalid state')
            sipTransactions[sipCallId] = sipState.INVALID
            sipTransactionsList.append(sipMsgTransaction)
    else:                                               # SipTransaction has been processed.
        # Sip state machine, obtain existing SIP Transaction
        if sipCallId in sipTransactions[sipCallId]:
            # SipTransaction is being processed.
            status = findSipMsgStatus(sipMessage)
            #STATE - CALLING:
            if sipTransactions[sipCallId] == 1:
                logging.info("CALLING state")
                if status == None:
                    sipTransactions[sipCallId] = sipState.INVALID
                elif status >=100 and status <=199:
                    sipTransactions[sipCallId] = sipState.PROCEEDING
                elif status >=200 and status <=299:                    
                    sipTransactions[sipCallId] = sipState.TERMINATED
                elif status >=300 and status <=699:
                    sipTransactions[sipCallId] = sipState.COMPLETED
                else:
                    logging.info("CALLING state - Message: " + sipMessage)
            #STATE - PROCEEDING:
            elif sipTransactions[sipCallId] == 2:
                logging.info("PROCEEDING state")
                if status == None:
                    sipTransactions[sipCallId] = sipState.INVALID
                elif status >=100 and status <=199:
                    # Remains in same State
                    sipTransactions[sipCallId] = sipState.PROCEEDING
                elif status >=200 and status <=299:
                    sipTransactions[sipCallId] = sipState.TERMINATED
                elif status >=300 and status <=699:
                    sipTransactions[sipCallId] = sipState.COMPLETED
                else:
                    logging.info("PROCEEDING state - Message: " + sipMessage)
            #STATE - COMPLETED:
            elif sipTransactions[sipCallId] == 3:
                logging.info("COMPLETED state")
                logging.info("Timer D started")

            elif sipTransactions[sipCallId] == 4:
                logging.info("TERMINATED state")
            else:
                logging.error('sipStateMachine Invalid state')
                sipTransactions[sipCallId] = sipState.INVALID
                

# Process WS Packet from Wire
def processWsPacket(wsMsg,ipInfo):
    logging.info("------------------------------------------------------Processing WS message------------------------------------------------------")
    print "------------------------------------------------------Processing WS message------------------------------------------------------"
    wsData = wsMsg.split('\r\n')
    print wsData

# Process SIP Packet from Wire, once packet has been received completely (Include TCP Fragmentation)
#@profile
def processSipPacket(sipMsg,ipInfo):
    logging.info("------------------------------------------------------processSipPacket() App Processing SIP message------------------------------------------------------")
    print "------------------------------------------------------processSipPacket() App Processing SIP message------------------------------------------------------"
    #ipInfo = [str(protocol),str(s_addr),str(source_port),str(d_addr),str(dest_port)]
    #Remove Lines
    sipData = sipMsg.split('\r\n')
    # Create sipMessage Object for each SIP Packet received
    newSipMessage = sipMessage()
    newSipMessage.setSipMsgIpInfo(ipInfo)

    if sipLocatorConfig.ENABLE_SIPCLF:
        sipClfMessage = sipClf()
        sipClfMessage.setSipMsgIpInfo(ipInfo)

    #Index SDP Values
    sdpLine = 1
    try:
        for sipLine in sipData:
            #print 'processSipPacket() sipLine: ' + sipLine
            Message = re.search(r'(\w+\s+sip:.*)|(^SIP/2.0\s.*)', sipLine)
            Header  = re.search(r'(^\w+:) (.*)|([A-Za-z]+-[A-Za-z]+:) (.*)', sipLine)
            SDP     = re.search(r'(^[A-Za-z]){1}=(.*)', sipLine)
            if Message:
                # Find Method Name or SIP Response
                #print 'processSipPacket() SIP Method: ' + newSipMessage.getSipMsgMethod()
                message = Message.group(0)
                # SIPCLF
                if sipLocatorConfig.ENABLE_SIPCLF:
                    sipClfMessage.setSipMessage(message)
                    logging.info("processSipPacket() - ENABLE_SIPCLF True")

                newSipMessage.setSipMessage(message)
                sipClfMessage.setSipMessage(message)
                logging.info("processSipPacket() - SIP Method: " + message)
                Message = None #Update to None

            if Header:
                # Matches Header no hyphen, (Example: Contact)   
                headerKey   = Header.group(1)
                headerValue = Header.group(2)
                # There is a hyphen (Example: Content-Type)
                if ((headerKey == None) and (headerValue == None)):
                    headerKey   = Header.group(3)
                    headerValue = Header.group(4) 
                # Add Values to Object          
                newSipMessage.addSipHeader(headerKey,headerValue)

                if sipLocatorConfig.ENABLE_SIPCLF:
                    sipClfMessage.addSipHeader(headerKey,headerValue) 

                Header = None #Update to None
            if SDP:
                sdpKey = SDP.group(1)
                sdpValue = SDP.group(2)
                newSipMessage.addSdpInfo(sdpLine,sdpKey,sdpValue)
                if sipLocatorConfig.ENABLE_SIPCLF:
                    sipClfMessage.addSdpInfo(sdpLine,sdpKey,sdpValue)
                sdpLine = sdpLine + 1
                SDP = None #Update to None

        sipStateMachine(newSipMessage)
        ccSipEngine(newSipMessage)
        del newSipMessage

        if sipLocatorConfig.ENABLE_SIPCLF:
            ccSipClfEngine(sipClfMessage)
            del sipClfMessage

    except Exception,e:
        logging.error("processSipPacket() - Exception - " + str(e))
        print traceback.format_exc()
        print e  

# Send an SMS Message via Twilio Client
# sipLocatorConfig file contains parameters

def notifyViaSms(textMessage):
    # Your Account Sid and Auth Token from twilio.com/user/account
    try:
        client = TwilioRestClient(sipLocatorConfig.TWILIO_ACCOUNT_SID, sipLocatorConfig.TWILIO_AUTH_TOKEN)
        message = client.sms.messages.create(body=textMessage,
        to=sipLocatorConfig.TWILIO_TO_PHONE,    # Replace with your phone number
        from_=sipLocatorConfig.TWILIO_FROM_PHONE) # Replace with your Twilio number
        print message.sid + " notifyViaSms() SMS Sent successfully!"
        logging.info('notifyViaSms() - ' + str(message.sid) + ' SMS Sent successfully!')
    except Exception,e:
        logging.error("notifyViaSms() - Exception - Unable to send SMS message " + str(e))
        print traceback.format_exc()
        print e

# validTcpPort
# Verifies if its a Valid IP port 1-65535
def validTcpPort(port):
    try:
        if port>=1 and port <=65535:
            return True
        else:
            return False
    except:
        return False

# validIpAddress
# Verifies if its a Valid IP address
def validIpAddress(address):
    try: 
        socket.inet_aton(address)
        #logging.info('validIpAddress() - True - ' + str(address))
        return True
    except:
        return False

# ccProcessSipInformation
# Returns real IP address
def ccProcessSipInformation(sipMsg):
    # Process SIP Message IP Address Information
    try:
        sipMsgIpInfo = sipMsg.getSipMsgIpInfo()
        logging.info("ccProcessSipInformation() - Source IP Address: " + sipMsgIpInfo.get('s_addr'))
        
        if sipLocatorConfig.SIP_PROXY_HOSTNAME != None:
            logging.info("ccProcessSipInformation() - sipLocatorConfig.SIP_PROXY_HOSTNAME is configured. Verifying Proxy address(es): " + ','.join(sipLocatorConfig.SIP_PROXY_HOSTNAME))

        if sipMsgIpInfo.get('s_addr') in sipLocatorConfig.SIP_PROXY_HOSTNAME:
            logging.info("ccProcessSipInformation() - Using SIP_PROXY_HOSTNAME: " + sipMsgIpInfo.get('s_addr') + " looking for real IP Address...")
            sipTagRegex = r".*;" + re.escape(sipLocatorConfig.SIP_PROXY_TAG) + r"=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3});.*"
            Message = re.search(sipTagRegex, sipMsg.getSipHeaders().get("Contact:"))
            if validIpAddress(Message.group(1)):
                logging.info("ccProcessSipInformation() - SIP Message Source IP Address: " + Message.group(1))
                return Message.group(1)
            else:
                #Add Code to support other SIP Headers
                logging.error("ccProcessSipInformation() - SIP Message Source IP Address Not Found in Headers")
                return sipMsgIpInfo.get('s_addr')
        # Convert PRIVATE to OUTSIDE IP Address        
        elif sipMsgIpInfo.get('s_addr') == sipLocatorConfig.SIP_PRIVATE_HOSTNAME:
            logging.info("ccProcessSipInformation() - Using SIP_PRIVATE_HOSTNAME: " + sipMsgIpInfo.get('s_addr') + " converting to public IP address: " + sipLocatorConfig.SIP_PUBLIC_HOSTNAME)
            if validIpAddress(sipLocatorConfig.SIP_PUBLIC_HOSTNAME):
                logging.info("ccProcessSipInformation() - SIP Message Source IP Address: " + sipLocatorConfig.SIP_PUBLIC_HOSTNAME)
                return sipLocatorConfig.SIP_PUBLIC_HOSTNAME
            else:
                #Add Code to support other SIP Headers
                logging.error("ccProcessSipInformation() - SIP Message Invalid value in parameter SIP_PUBLIC_HOSTNAME" + sipLocatorConfig.SIP_PUBLIC_HOSTNAME)
                return sipMsgIpInfo.get('s_addr')  
        else:
            return sipMsgIpInfo.get('s_addr')       
    except Exception,e:
        logging.error('ccProcessSipInformation() - Exception - Unable to get IP address src - ' + str(e))
        print traceback.format_exc()
        print e
        return "0.0.0.0"

# ccClfEngine
# Verifies if its a new call and contacts SIP Parse to upload info
#@profile
def ccSipClfEngine(sipMsg):
    #Obtain SipCLF fields   
    try:
        thread = Thread(target=sipMsg.processSipMsgClf,args = ( ))
        thread.daemon = True
        thread.start()
#       thread.join()
    except Exception,e:
        logging.error("ccSipClfEngine() - Exception calling processSipMsgClf()" + str(e))
        print traceback.format_exc()
        print e

    # Print fields
    if sipLocatorConfig.SIP_CLF_DEBUG:    
        try:
            thread = Thread(target=sipMsg.printSipMsgClf,args = (True, )) # <--- True Create SIP CLF Record
            thread.daemon = True
            thread.start()
    #        thread.join()
        except Exception,e:
            logging.error("ccSipClfEngine() - Exception calling printSipMsgClf()" + str(e))
            print traceback.format_exc()
            print e

# ccSipEngine
# Verifies if its a new call and contacts SIP Parse to upload info
#@profile
def ccSipEngine(sipMsg):

    # Check if sipMsg contains SDP
    sipMsg.processSipMsgSdp()
    # Update SIP Msg object with CallID
    sipMsg.processSipMsgCallId()
    # Insert sipMsg to Local Array
    sipMessagesList.append(sipMsg)

    #Store SIP Message in Parse
    # sipMessageInsertViaParse(sipMsg)
    if sipLocatorConfig.ENABLE_PARSE:
        try:
            thread = Thread(target=sipMessageInsertViaParse,args = (sipMsg, ))
            thread.daemon = True
            thread.start()
            thread.join()
        except Exception,e:
            logging.error("ccSipEngine() - Exception - found in sipMessageInsertViaParse()" + str(e))
            print 'ccSipEngine() - Exception - found in sipMessageInsertViaParse()'  + str(e)
            print traceback.format_exc()
            print e
 
    sipMessage = sipMsg.getSipMsgMethod()
    sipCallID  = sipMsg.getSipMsgCallId()


    #SIP Message INVITE found - New call
    if sipMessage.find('INVITE')!= -1:
        print 'ccSipEngine() - Total sipLocator calls: ' + str(len(sipCallListNumber))
        logging.info("ccSipEngine() - INVITE Message detected")
        print 'ccSipEngine() - INVITE Message detected: ' + sipMessage

        # First call in system (During system start)
        if len(sipCallListNumber) == 0:
            newSipCall = sipCall()
            newSipCall.setCallId(sipCallID)
            logging.info("ccSipEngine() - Initializing SipLocator List of Calls. New Call created. Call-ID: " + newSipCall.getSipCallId())

            #Add Calls
            sipCallListNumber.append(sipCallID)

            if sipMsg.isSipMsgLocal():
                logging.info('ccSipEngine() - Call Sent. Call-ID: ' + sipMsg.getSipMsgCallId())
                newSipCall.setLocalCall(True)
                sipProcessedCalls[newSipCall.getSipCallId()]=True
                sipClfCalls[newSipCall.getSipCallId()]=generateIdCode()             
            else:
                logging.info('ccSipEngine() - Call Received. Call-ID: ' + sipMsg.getSipMsgCallId())
                sipProcessedCalls[newSipCall.getSipCallId()]=False
                sipClfCalls[newSipCall.getSipCallId()]=generateIdCode()

            # Process Call GeoLocation
            if sipLocatorConfig.ENABLE_GEOLOCATION:     
                try:
                    sipSrcIpAddress = ccProcessSipInformation(sipMsg)
                    thread = Thread(target=newSipCall.setSipCallGeolocation,args = (processGeoLocation(sipSrcIpAddress), ))
                    thread.start()
                    thread.join()
                except Exception,e:
                    logging.error("ccSipEngine() - Exception calling setSipCallGeolocation()" + str(e))
                    print traceback.format_exc()
                    print e
                    
               # Process Call GeoPoint
                try:
                    geoLocationInfo = newSipCall.getSipCallGeoLocation()
                    if geoLocationInfo!=None:
                        geoLocationPoint = []
                        geoLocationPoint.append(geoLocationInfo['latitude'])
                        geoLocationPoint.append(geoLocationInfo['longitude'])
                        newSipCall.setSipCallGeoPoint(geoLocationPoint[0],geoLocationPoint[1])
                    else:
                        logging.error('ccSipEngine() - processGeoLocationPoint() Error. Empty GeoLocation info')
                        newSipCall.setSipCallGeoPoint(-1,-1)  
                except Exception,e:
                    print traceback.format_exc()
                    logging.error("ccSipEngine() - Exception calling processGeoLocationPoint()" + str(e))

            # Insert into Parse
            if sipLocatorConfig.ENABLE_PARSE:
                try:
                    thread = Thread(target=sipCallInsertViaParse,args = (newSipCall, ))
                    thread.start()
                    thread.join()
                    print 'ccSipEngine() - sipCallInsertViaParse()'
                except Exception,e:
                    print traceback.format_exc()
                    logging.error("ccSipEngine() - Exception calling sipCallInsertViaParse()" + str(e))

            # Enable SMS Notifications
            if sipLocatorConfig.ENABLE_SMS_NOTIFICATIONS:
                try:
                    thread = Thread(target=notifyViaSms,args = ("New call has been processed To:  " + sipMsg.getSipHeaders().get("To:"), ))
                    thread.start()
                    thread.join()
                    print 'ccSipEngine() - calling notifyViaSms()'
                except Exception,e:
                    logging.error("ccSipEngine - Exception calling notifyViaSms()" + str(e))
                    print traceback.format_exc()
                    print e
                    
        else:
            # Check each call Object and verify Call-ID does not exist. If does not exist, insert new call, otherwise is a SIP Re-Invite
            print 'ccSipEngine() - Total sipLocator calls: ' + str(len(sipCallListNumber))
            if not sipCallID in sipCallListNumber:
                logging.info("ccSipEngine() New Call created. Call-ID: " + sipCallID)
                #print 'ccSipEngine() New Call created. Call-ID: ' + sipCallID
                newSipCall = sipCall()
                newSipCall.setCallId(sipCallID)
                
                if sipMsg.isSipMsgLocal():
                    logging.info('ccSipEngine() - Call Sent. Call-ID: ' + sipMsg.getSipMsgCallId())
                    newSipCall.setLocalCall(True)
                    sipProcessedCalls[newSipCall.getSipCallId()]=True
                    sipClfCalls[newSipCall.getSipCallId()]=generateIdCode()                   
                else:
                    logging.info('ccSipEngine() - Call Received. Call-ID: ' + sipMsg.getSipMsgCallId())
                    sipProcessedCalls[newSipCall.getSipCallId()]=False
                    sipClfCalls[newSipCall.getSipCallId()]=generateIdCode()
                        
                sipCallListNumber.append(sipCallID)

                # Process Call GeoLocation 
                if sipLocatorConfig.ENABLE_GEOLOCATION:                           
                    try:
                        sipSrcIpAddress = ccProcessSipInformation(sipMsg)
                        thread = Thread(target=newSipCall.setSipCallGeolocation,args = (processGeoLocation(sipSrcIpAddress), ))
                        thread.start()
                        thread.join()
                        logging.info('ccSipEngine() - setSipCallGeolocation()')
                    except Exception,e:
                        logging.error('ccSipEngine() - setSipCallGeolocation() Error')
                        print traceback.format_exc()
                        print e
                        
                    # Process Call GeoPoint
                    try:
                        geoLocationInfo = newSipCall.getSipCallGeoLocation()
                        if geoLocationInfo!=None:
                            geoLocationPoint = []
                            geoLocationPoint.append(geoLocationInfo['latitude'])
                            geoLocationPoint.append(geoLocationInfo['longitude'])
                            newSipCall.setSipCallGeoPoint(geoLocationPoint[0],geoLocationPoint[1])
                        else:
                            print 'ccSipEngine() - processGeoLocationPoint() Error. Empty GeoLocation info'
                            newSipCall.setSipCallGeoPoint(-1,-1)  
                    except Exception,e:
                        logging.error('processGeoLocationPoint() Error')
                        print traceback.format_exc()
                        print e

                # Multi-threading
                if sipLocatorConfig.ENABLE_PARSE:
                    try:
                        thread = Thread(target=sipCallInsertViaParse,args = (newSipCall, ))
                        thread.daemon = True
                        thread.start()
                        thread.join()
                    except Exception,e:
                        logging.error("ccSipEngine() - Exception calling sipCallInsertViaParse()" + str(e))
                        print traceback.format_exc()
                        print e
                
                # Enable SMS Notifications
                if sipLocatorConfig.ENABLE_SMS_NOTIFICATIONS:
                    try:
                        thread = Thread(target=notifyViaSms,args = ("New call has been processed To:  " + sipMsg.getSipHeaders().get("To:"), ))
                        thread.daemon = True
                        thread.start()
                        thread.join()
                        print 'ccSipEngine() notifyViaSms()'
                    except Exception,e:
                        logging.error("ccSipEngine Exception calling notifyViaSms()" + str(e))
                        print traceback.format_exc()
                        print e

            else:
                logging.info('ccSipEngine() Re-Invite detected().')
                print 'ccSipEngine() Re-Invite detected().'    

#Connects to Parse using parse_rest
#https://github.com/dgrtwo/ParsePy
#@profile
def sipCallInsertViaParse(sipCall):
    # Connects to Parse via initial settings and created object
    try:
        sipCall.save()
        logging.info("sipCallInsertViaParse() - sipCall Record created in Parse CallID: " + sipCall.getSipCallId())            
        print 'sipCallInsertViaParse() - sipCall Record created in Parse CallID: ' + sipCall.getSipCallId()
    except Exception,e:
        logging.error('sipCallInsertViaParse() - Exception - ' + str(e))
        print 'sipCallInsertViaParse() - Exception'
        print traceback.format_exc()
        print e

#Connects to Parse using parse_rest
#https://github.com/dgrtwo/ParsePy
#@profile
def sipMessageInsertViaParse(sipMsg):
    # Connects to Parse via initial settings and created object
    try:
        sipMsg.save()
        logging.info("sipMessageInsertViaParse() - sipMessage Record created in Parse. " + sipMsg.getSipMsgMethod() + " CallID: " + sipMsg.getSipMsgCallId())
        print 'sipMessageInsertViaParse() - sipMessage Record created in Parse. ' + sipMsg.getSipMsgMethod() + ' CallID: ' + sipMsg.getSipMsgCallId()
    except Exception,e:
        logging.error('sipMessageInsertViaParse() - Exception: ' + str(e))
        print 'sipMessageInsertViaParse() - Exception'
        print traceback.format_exc()
        print e

#Convert a string of 6 characters of ethernet address into a dash separated hex string
#@profile
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

def printHex(data):
    hex = binascii.hexlify(data)
    formatted_hex = ':'.join(hex[i:i+2] for i in range(0, len(hex), 2))
    logging.info('\nHex data: \n%s\n\n', formatted_hex)

#Catch all TCP fragmented
def _sipTcpReceiver(socket,firstSipPacket):
    #Add the existing data from first check
    logging.info('-----------------------------------------------_sipTcpReceiver()------------------------------------------------')
    fragmentNumber = 1
    packetCount    = 1
    sipPacketCount = 1
    
    if not firstSipPacket:logging.info('_sipTcpReceiver() - Empty App firstSipPacket segment');return None # No Content length yet

    #logging.info('_sipTcpReceiver() fragment (%d). Initial App data: <![_sipTcpReceiver[%s]]>\n',fragmentNumber,firstSipPacket)
    sipMsg = firstSipPacket
    #Verify if first TCP packet is fragmented
    index1, index2 = sipMsg.find('\n\n'), sipMsg.find('\n\r\n')
    logging.info('index1 (%d) index2 (%d)',index1,index2)
    if index2 > 0:
        index = index2 + 3
        match = re.search(r'content-length\s*:\s*(\d+)\r?\n', sipMsg.lower())
        if not match: 
            logging.warn('_sipTcpReceiver() - No Content-Length found') #- Pending further content.
        else:
            length = int(match.group(1))
            if len(sipMsg) == index + length: 
                logging.info('_sipTcpReceiver() - No TCP Fragmentation detected. Packet Length(%d)',index+length) # No pending further content.
                logging.info('_sipTcpReceiver() - Fragment (%d). Final sip Packet <![_sipTcpReceiver[%s]]>\n', fragmentNumber, firstSipPacket)
                return firstSipPacket
            else:
                logging.info('_sipTcpReceiver() - TCP Fragmentation detected Pending further content. Packet Length(%d)',index+length)

    # TCP Fragmentation detected - Pending further content.
    pending = firstSipPacket

    while True:
        #logging.info('******* Packet count(%d) - Sip packets(%d)',packetCount,sipPacketCount)
        # Get more info from existing socket and verify if TCP fragmentation exists.
        # Is packet completed
        try:
            # Obtain next TCP fragment Ethernet 14 byte, IP 20 bytes, TCP 32 bytes -> 66 bytes
            packet = socket.recv(sipLocatorConfig.NETWORK_TCP_MAX_SIZE)
            #logging.info('********** _sipTcpReceiver() Reading new packet from OS()->')
            packetCount = packetCount + 1
            #Parse ethernet header
            eth_length = 14
            ip_header = packet[eth_length:20+eth_length]          
            #now unpack them 
            iph = unpack('!BBHHHBBH4s4s' , ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            ttl = iph[5]
            protocol = iph[6]
            t = iph_length + eth_length           
            tcp_header = packet[t:t+20]  # TODO: Ip header can be variable >= 20 TCP Offset support
            #now unpack them 
            tcph = unpack('!HHLLBBHHH',tcp_header)
            source_port = tcph[0]
            dest_port = tcph[1]

            if (dest_port == sipLocatorConfig.SIP_PORT or source_port == sipLocatorConfig.SIP_PORT) and (protocol==6):
                sipPacketCount = sipPacketCount + 1
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size
                #get data from the packet
                data = packet[h_size:]
                #logging.info('_sipTcpReceiver extracted fragment number (%d). Extracted App data  <![sipLocator[%s]]>',fragmentNumber,data)
                # Pending is True as initial data exists

                if h_size <= 66 and len(data) == 0:
                    #logging.warn('_sipTcpReceiver() no App content (Possible a TCP Acknowledgement) - Header size: (%d)',h_size)
                    continue;

                if pending:
                    fragmentNumber = fragmentNumber + 1                 
                    #logging.info('_sipTcpReceiver() fragment (%d). Length (%d) - Header size: (%d)',fragmentNumber,len(data),h_size)
                    #logging.info('_sipTcpReceiver() App data extracted <![_sipTcpReceiver[%s]]>\n',data )
                    pending += data
                    while True:
                        msg = pending
                        index1, index2 = msg.find('\n\n'), msg.find('\n\r\n')
                        if index2 > 0 and index1 > 0:
                            if index1 < index2:
                                index = index1 + 2
                            else: 
                                index = index2 + 3
                        elif index1 > 0: 
                                index = index1 + 2
                        elif index2 > 0:
                                index = index2 + 3
                        else:
                            logging.warn('_sipTcpReceiver() - no CRLF found'); break # No header part yet
                        match = re.search(r'content-length\s*:\s*(\d+)\r?\n', msg.lower())
                        if not match: logging.warn('_sipTcpReceiver() - No Content-Length found'); break # no content length yet
                        length = int(match.group(1))
                        #logging.info('_sipTcpReceiver Sip data Up to index %d <![sipLocator[%s]]>\n', index,msg[:index+length])
                        #logging.info('_sipTcpReceiver Index: %d Length: %d Sip data Body <![_sipTcpReceiver[%s]]>\n\n', index, index+length, msg[:index+length])
                        if len(msg) < index + length: logging.info('_sipTcpReceiver - Fragment (%d). App Message has more content: %d < %d (%d+%d)', fragmentNumber, len(msg), index+length, index, length);break # pending further content.
                        total, pending = msg[:index+length], msg[index+length:]
                        #logging.info('_sipTcpReceiver pending App data <![sipLocator[%s]]>\n', pending)
                        logging.info('_sipTcpReceiver() - Fragment (%d). Final sip Packet <![_sipTcpReceiver[%s%s]]>\n', fragmentNumber, total,pending)
                        return total+pending
                else:
                    logging.warn('_sipTcpReceiver() - Empty packet')
                    break
                    # else signal a failure
            else:
                logging.warn('_sipTcpReceiver() - Discard packet for processing during TCP reassambly. Non SIP Packet')

        except Exception,e:
            # Something else happened, handle error, etc.
            logging.error('_sipTcpReceiver() - Exception - processing TCP fragmentation ' + str(e)) 
            print e

#@profile 
def initPacketCapture(): 
    logging.info("-----------------------------------------------Server packet capture started------------------------------------------------")
    print "-----------------------------------------------Server packet capture started------------------------------------------------"
    print
    
    #create a AF_PACKET type raw socket (thats basically packet level)
    #define ETH_P_ALL   0x0003          /* Every packet (be careful!!!) */
    #define ETH_P_IP    0x0800          /* Only IP Packets */
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(sipLocatorConfig.NETWORK_FILTER))
    except socket.error, msg:
        print 'initPacketCapture() - Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit(1)   
    except Exception,e:
        print e
        sys.exit(1)

    # Receive a packet
    while True:
        packet = s.recvfrom(sipLocatorConfig.NETWORK_MAX_SIZE)
        #packet string from tuple
        packet = packet[0] 
        #parse ethernet header
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        #print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
     
        #Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8 :
            #Parse IP header
            #take first 20 characters for the ip header
            ip_header = packet[eth_length:20+eth_length]          
            #now unpack them :)
            iph = unpack('!BBHHHBBH4s4s' , ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
     
            #TCP protocol
            if protocol == 6:
                t = iph_length + eth_length
                tcp_header = packet[t:t+20]
                #now unpack them :)
                tcph = unpack('!HHLLBBHHH' , tcp_header)
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                if dest_port == sipLocatorConfig.SIP_PORT or source_port == sipLocatorConfig.SIP_PORT:

                    h_size = eth_length + iph_length + tcph_length * 4
                    data_size = len(packet) - h_size
                    #get data from the packet
                    data = packet[h_size:] 
                
                    # Change to Dictionary Data 'protocol','s_addr','source_port','d_addr','dest_port'
                    # member['sipMsgSdpInfo'] = parseSipMsg.getSdpInfo()
                    #ipInfo = [str(protocol),str(s_addr),str(source_port),str(d_addr),str(dest_port)]
                    ipInfo = {}
                    ipInfo['protocol'] = protocol
                    ipInfo['s_addr'] = str(s_addr)
                    ipInfo['source_port'] = source_port
                    ipInfo['d_addr'] = str(d_addr)
                    ipInfo['dest_port'] = dest_port
                    
                    print
                    logging.info("------------------------------------------------------initPacketCapture() Stack processing SIP Packet------------------------------------------------------")
                    print "------------------------------------------------------initPacketCapture() Stack processing TCP SIP Packet------------------------------------------------------"
                    logging.info('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))                   
                    print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
                    logging.info('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                    print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
                   
                    # process SIP information (Check retransmissions) - #sipData = _sipTcpReceiver(s,data)
                    sipData = _sipTcpReceiver(s,data)                                

                    if sipData is not None:
                        try:
                            thread = Thread(target=processSipPacket,args = (sipData,ipInfo,))
                            thread.daemon = True
                            thread.start()
                            print 'initPacketCapture() - processSipPacket()'
                        except Exception,e:
                            logging.error("initPacketCapture - Exception calling processSipPacket()" + str(e))
                            print traceback.format_exc()
                            print e

                # Add WebSockets library TODO
                if dest_port == sipLocatorConfig.WS_PORT:   
                    h_size = eth_length + iph_length + tcph_length * 4
                    data_size = len(packet) - h_size
                    #get data from the packet
                    data = packet[h_size:] 
                    # Change to Dictionary Data 'protocol','s_addr','source_port','d_addr','dest_port'
                    ipInfo = {}
                    ipInfo['protocol'] = protocol
                    ipInfo['s_addr'] = str(s_addr)
                    ipInfo['source_port'] = source_port
                    ipInfo['d_addr'] = str(d_addr)
                    ipInfo['dest_port'] = dest_port
                    # TODO Process WS

            #ICMP Packets
            elif protocol == 1 :
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u+4]
     
                #now unpack them :)
                icmph = unpack('!BBH' , icmp_header)
                 
                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]
                 
                print 'ICMP Packet - Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
                 
                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size
                 
                #get data from the packet
                data = packet[h_size:]           
                #print 'Data : ' + data
     
            #UDP packets
            elif protocol == 17 :
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u+8]
                #now unpack them :)
                udph = unpack('!HHHH' , udp_header)
                 
                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]
                                   
                if dest_port == sipLocatorConfig.SIP_PORT:
                    logging.info("-----------------------------------------------Stack detected SIP UDP SIP data-----------------------------------------------")
                    print "-----------------------------------------------Stack detected SIP UDP SIP data-----------------------------------------------"
                    logging.info('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                    print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
                    logging.info('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))
                    print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)                       
                    print "-------------------------------------------------------------------------------------------------------------------------------"
                    logging.info('-------------------------------------------------------------------------------------------------------------------------------')
          
                    h_size = eth_length + iph_length + udph_length
                    data_size = len(packet) - h_size                     
                 
                    #get data from the packet
                    data = packet[h_size:] 
                    # Change to Dictionary Data 'protocol','s_addr','source_port','d_addr','dest_port'
                    ipInfo = {}
                    ipInfo['protocol'] = protocol
                    ipInfo['s_addr'] = str(s_addr)
                    ipInfo['source_port'] = source_port
                    ipInfo['d_addr'] = str(d_addr)
                    ipInfo['dest_port'] = dest_port

                    try:
                        thread = Thread(target=processSipPacket,args = (data,ipInfo,))
                        thread.daemon = True
                        thread.start()
                        print 'initPacketCapture() - processSipPacket()'
                    except Exception,e:
                        logging.error("initPacketCapture - Exception calling processSipPacket()" + str(e))
                        print traceback.format_exc()
                        print e

            #some other IP packet like IGMP
            else :
                logging.error('Packet - Protocol other than TCP/UDP/ICMP')
                print 'Packet - Protocol other than TCP/UDP/ICMP'

# Trace settings for SIP CLF format function (%(threadName)s)
def traceSettings(logdir=None, scrnlog=False, txtlog=True, loglevel=logging.DEBUG):
    try:
        logdir = os.path.abspath(logdir)
        if not os.path.exists(logdir):
            os.mkdir(logdir)

        log = logging.getLogger('sipClf.core')
        log.setLevel(loglevel)

        log_formatter = logging.Formatter("%(asctime)s.%(msecs).03d %(levelname)s %(message)s", datefmt='%m/%d/%Y %I:%M:%S')

        if txtlog:
            txt_handler = RotatingFileHandler(os.path.join(logdir, "sipClfRecord.log"), backupCount=5)
            txt_handler.doRollover()
            txt_handler.setFormatter(log_formatter)
            log.addHandler(txt_handler)
            log.info("SIP Clf Logger initialized.")

        if scrnlog:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(log_formatter)
            log.addHandler(console_handler)
    except Exception,e:
        print e

#@profile
def main():
    try:
        traceSettings('logs')
        if not os.path.exists('logs'):
            os.makedirs('logs')
    except OSError:
        pass

    try:
        global sipClfLog
        sipClfLog = logging.getLogger('sipClf.core')
        logging.basicConfig(filename='logs/sipLocator.log', level=logging.INFO, format='%(asctime)s.%(msecs).03d %(levelname)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S')   
        logging.info("-----------------------------------------------Initializing sipLocator server-----------------------------------------------")        
        print "-----------------------------------------------Initializing sipLocator server-----------------------------------------------"
        initPacketCapture()
        sipClfLog.debug('Sip CLF Engine started')
    except KeyboardInterrupt:
        logging.info ("sipLocator server stopping....")
        try:
            sys.stdout.close()
        except:
            pass
        try:
            sys.stderr.close()
        except:
            pass
    except Exception,e:
        logging.error("Exception found " + str(e))
    except (IOError, OSError):
       pass
        
if __name__ == '__main__':
    main()