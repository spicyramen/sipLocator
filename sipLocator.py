'''
@author Gonzalo Gasca Meza
        AT&T Labs 
        Date: September 2013
        Purpose: Sniffs all incoming and outgoing SIP packets and upload geoLocation information to parse.com
'''
import sipLocatorConfig
import socket,sys,logging,traceback,re,urllib,ast
from parse_rest.connection import register
from parse_rest.datatypes import Object,GeoPoint
from threading import Thread
from struct import *

#import psutil
#from memory_profiler import profile


sys.excepthook = lambda *args: None

# Global variables
register(sipLocatorConfig.APPLICATION_ID, sipLocatorConfig.REST_API_KEY)
sipCallList = []
sipMessagesList = []

class sipCall(Object):

    """Create a SIP Call Object"""
    def __init__(self):
        logging.info("sipCall() New sipCall object created()")
        print 'sipCall() New sipCall object created()'
        self.sipCallID = ''
        self.sipCallGeoPoint = GeoPoint(latitude=0.0, longitude=0.0)
        self.sipCallGeoLocation = {}
     
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
    
        

class sipMessage(Object):

    """Create a SIP Message Object"""

    def __init__(self):
        logging.info("sipMessage() New sipMessage object created()")
        print 'sipMessage() New sipMessage object created()'
        self.sipHeaderInfo    = {}
        self.sipMsgSdpInfo    = {}
        self.hasSDP           = False
        self.sipMsgMethodInfo = ''
        self.sipMsgCallId     = ''
    
    def setSipMessage(self,msg):
        self.sipMsgMethodInfo = msg
  
    def getSipMsgMethod(self):
        return self.sipMsgMethodInfo

    def addSipHeader(self,header,value):      
        self.sipHeaderInfo.update({header: value})
        logging.info(header + ' ' + value)
        #print header + ' ' + value
        #print 'sipMessage() addHeader ' + 'Header: ' + header + ' Value: ' + value
    
    def addSdpInfo(self,sdpKey,sdpValue):      
        self.sipMsgSdpInfo.update({sdpKey: sdpValue})
        logging.info(sdpKey + '=' + sdpValue)
        #print sdpKey + '=' + sdpValue
        #print 'sipMessage() addHeader ' + 'Header: ' + header + ' Value: ' + value

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
            #logger.info('getSipCallId() Sip Call-ID: ' + callInfo.get('Call-ID:'))
            return callInfo
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
                    #logging.info("processSipMsgSdp() SDP found")
                    #print 'processSipMsgSdp() SDP found'
                    self.hasSDP = True
            else:
                # No SDP  
                self.hasSDP = False
        # Not all SIP Message contain SDP nor Content-Type        
        except KeyError:    
            pass    
        except Exception,e:
            print traceback.format_exc()
            print 'processSipMsgSdp() Error'


#Obtain geoLocation
def processGeoLocation(srcIP):
        try:
            if srcIP!="":
                response = urllib.urlopen('http://freegeoip.net/json/' + srcIP ).read()
                geoLocationInfo = response.splitlines()
                # Obtain Dictionary
                finalGeoLocationPoint  = ast.literal_eval(geoLocationInfo[0])
                print finalGeoLocationPoint
                return finalGeoLocationPoint
            else:
                print 'processGeoLocation() Error'
        except Exception,e:
            print traceback.format_exc()
            print 'processGeoLocation() Exception'


# Process WS Packet from Wire
def processWsPacket(wsMsg,ipInfo):
    logging.info("------------------------------------------------------Processing WS message------------------------------------------------------")
    print "------------------------------------------------------Processing WS message------------------------------------------------------"
    wsData = wsMsg.split('\r\n')
    print wsData

# Process SIP Packet from Wire
#@profile
def processSipPacket(sipMsg,ipInfo):
    logging.info("------------------------------------------------------Processing SIP message------------------------------------------------------")
    print "------------------------------------------------------Processing SIP message------------------------------------------------------"
    #ipInfo = [str(protocol),str(s_addr),str(source_port),str(d_addr),str(dest_port)]
    #Remove Lines
    sipData = sipMsg.split('\r\n')
    # Create sipMessage Object for each SIP Packet received
    newSipMessage = sipMessage()
    newSipMessage.setSipMsgIpInfo(ipInfo)

    try:
        for sipLine in sipData:
            #print 'processSipPacket() sipLine: ' + sipLine
            Message = re.search(r'(\w+\s+sip:.*)|(^SIP/2.0\s.*)', sipLine)
            Header  = re.search(r'(^\w+:) (.*)|([A-Za-z]+-[A-Za-z]+:) (.*)', sipLine)
            SDP     = re.search(r'(^[A-Za-z])=(.*)', sipLine)
            if Message:
                # Find Method Name or SIP Response
                message = Message.group(0)
                newSipMessage.setSipMessage(message)
                logging.info("processSipPacket() SIP Method: " + newSipMessage.getSipMsgMethod())
                #print 'processSipPacket() SIP Method: ' + newSipMessage.getSipMsgMethod()
                Message = None
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
                Header = None
            if SDP:
                sdpKey = SDP.group(1)
                sdpValue = SDP.group(2)
                newSipMessage.addSdpInfo(sdpKey,sdpValue)
                SDP = None

        # Process sipHeaders
        #newSipMessage.getSipHeaders()
        # Process sip SDP info
        #newSipMessage.getSdpInfo()
        # Process SIP Message                 
        ccEngine(newSipMessage)
        del newSipMessage

    except Exception,e:
        logging.error("processSipPacket() Exception found " + str(e))    


# CcEngine
# Verifies if its a new call and contacts SIP Parse to upload info
#@profile
def ccEngine(sipMsg):

    # Check if sipMsg contains SDP
    sipMsg.processSipMsgSdp()
    # Update SIP Msg object with CallID
    sipMsg.processSipMsgCallId()
    # Insert Local Array
    sipMessagesList.append(sipMsg)
    
    # Store SIP Message in Parse
    # Create a New Thread
    try:
        thread = Thread(target=sipMessageInsertViaParse,args = (sipMsg, ))
        thread.start()
        thread.join()
    except Exception,e:
        print traceback.format_exc()
        print 'sipMessageInsertViaParse() Error'

    #sipMessageInsertViaParse(sipMsg)
    sipMessage = sipMsg.getSipMsgMethod()
    sipCallID  = sipMsg.getSipMsgCallId()

    if sipMessage.find('INVITE')!= -1:
        print 'Total sipLocator calls: ' + str(len(sipCallList))
        logging.info("ccEngine() INVITE Message detected")
        print 'ccEngine() INVITE Message detected: ' + sipMessage
        if len(sipCallList) == 0:
            newSipCall = sipCall()
            newSipCall.setCallId(sipCallID)
            logging.info("ccEngine() Initializing List of Calls. New Call created. Call-ID: " + newSipCall.getSipCallId())
            #print 'ccEngine() Initializing List of Calls. New Call created. Call-ID: ' + newSipCall.getSipCallId()
            # Process GeoLocation
            sipCallList.append(sipCallID)
           
            # Multi-threading
            # Process Call GeoLocation
            sipMsgIpInfo = sipMsg.getSipMsgIpInfo()
            
            try:
                thread = Thread(target=newSipCall.setSipCallGeolocation,args = (processGeoLocation(sipMsgIpInfo.get('s_addr')), ))
                thread.start()
                thread.join()
                #print 'ccEngine() setSipCallGeolocation()'
            except Exception,e:
                print traceback.format_exc()
                print 'setSipCallGeolocation() Error'

           # Process Call GeoPoint
            try:
                geoLocationInfo = newSipCall.getSipCallGeoLocation()
                if geoLocationInfo!=None:
                    geoLocationPoint = []
                    geoLocationPoint.append(geoLocationInfo['latitude'])
                    geoLocationPoint.append(geoLocationInfo['longitude'])
                    newSipCall.setSipCallGeoPoint(geoLocationPoint[0],geoLocationPoint[1])
                else:
                    print 'processGeoLocationPoint() Error. Empty GeoLocation info'
                    newSipCall.setSipCallGeoPoint(-1,-1)  
            except Exception,e:
                print traceback.format_exc()
                print 'processGeoLocationPoint() Error'


            try:
                thread = Thread(target=sipCallInsertViaParse,args = (newSipCall, ))
                thread.start()
                thread.join()
                print 'ccEngine() sipCallInsertViaParse()'
            except Exception,e:
                print traceback.format_exc()

        else:
            # Check each call Object and verify Call-ID does not exist. If does not exist, insert new call, otherwise is a SIP Re-Invite
            print 'Total sipLocator calls: ' + str(len(sipCallList))
            if not sipCallID in sipCallList:
                logging.info("ccEngine() New Call created. Call-ID: " + sipCallID)
                #print 'ccEngine() New Call created. Call-ID: ' + sipCallID
                newSipCall = sipCall()
                newSipCall.setCallId(sipCallID)

                # Process Call GeoLocation
                sipMsgIpInfo = sipMsg.getSipMsgIpInfo()

                try:
                    thread = Thread(target=newSipCall.setSipCallGeolocation,args = (processGeoLocation(sipMsgIpInfo.get('s_addr')), ))
                    thread.start()
                    thread.join()
                    logging.info('ccEngine() setSipCallGeolocation()')
                except Exception,e:
                    print traceback.format_exc()
                    print 'ccEngine() setSipCallGeolocation() Error'

                # Process Call GeoPoint
                try:
                    geoLocationInfo = newSipCall.getSipCallGeoLocation()
                    if geoLocationInfo!=None:
                        geoLocationPoint = []
                        geoLocationPoint.append(geoLocationInfo['latitude'])
                        geoLocationPoint.append(geoLocationInfo['longitude'])
                        newSipCall.setSipCallGeoPoint(geoLocationPoint[0],geoLocationPoint[1])
                    else:
                        print 'processGeoLocationPoint() Error. Empty GeoLocation info'
                        newSipCall.setSipCallGeoPoint(-1,-1)  
                except Exception,e:
                    print traceback.format_exc()
                    print 'processGeoLocationPoint() Error'


                sipCallList.append(sipCallID)
                # Multi-threading
                try:
                    thread = Thread(target=sipCallInsertViaParse,args = (newSipCall, ))
                    thread.start()
                    thread.join()
                except Exception,e:
                    print traceback.format_exc()
                    print 'ccEngine() sipCallInsertViaParse() Error'
            else:
                logging.info('ccEngine() Re-Invite detected()')
                print 'ccEngine() Re-Invite detected()'    

#Connects to Parse using parse_rest
#https://github.com/dgrtwo/ParsePy
#@profile
def sipCallInsertViaParse(sipCall):
    # Connects to Parse via initial settings and created object
    try:
        sipCall.save()
        logging.info("sipCallInsertViaParse() sipCall Record created in Parse CallID: " + sipCall.getSipCallId())            
        print 'sipCallInsertViaParse() sipCall Record created in Parse CallID: ' + sipCall.getSipCallId()
    except Exception,e:
        logger.error('sipCallInsertViaParse() Error')
        print 'sipCallInsertViaParse() Error'

#Connects to Parse using parse_rest
#https://github.com/dgrtwo/ParsePy
#@profile
def sipMessageInsertViaParse(sipMsg):
    # Connects to Parse via initial settings and created object
    try:
        sipMsg.save()
        logging.info("sipMessageInsertViaParse() sipMessage Record created in Parse. " + sipMsg.getSipMsgMethod() + " CallID: " + sipMsg.getSipMsgCallId())
        print 'sipMessageInsertViaParse() sipMessage Record created in Parse. ' + sipMsg.getSipMsgMethod() + ' CallID: ' + sipMsg.getSipMsgCallId()
    except Exception,e:
        print 'sipMessageInsertViaParse() Error'


#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
 
#@profile 
def initPacketCapture() : 
    logging.info("-----------------------------------------------Server packet capture started------------------------------------------------")
    print "-----------------------------------------------Server packet capture started------------------------------------------------"
    print

    #create a AF_PACKET type raw socket (thats basically packet level)
    #define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    except socket.error, msg:
        print 'initPacketCapture() Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    # receive a packet
    while True:
        packet = s.recvfrom(65565) 
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
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);
     
      
            #TCP protocol

            if protocol == 6 :
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

                if dest_port == sipLocatorConfig.SIP_PORT:   
                    print               
                    logging.info("------------------------------------------------------SIP Packet detected------------------------------------------------------")
                    print "------------------------------------------------------SIP Packet detected------------------------------------------------------"
                    logging.info('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))                   
                    print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
                    logging.info('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))                    
                    print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)         
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
                    processSipPacket(data,ipInfo)
     
                if dest_port == sipLocatorConfig.WS_PORT:   
                    print               
                    logging.info("------------------------------------------------------WS Packet detected------------------------------------------------------")
                    print "------------------------------------------------------WS Packet detected------------------------------------------------------"
                    logging.info('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))                   
                    print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
                    logging.info('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))                    
                    print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)         
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
                    processWsPacket(data,ipInfo)


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
                    logging.info("-----------------------------------------------SIP Packet detected-----------------------------------------------")
                    print "-----------------------------------------------SIP Packet detected-----------------------------------------------"
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
                    processSipPacket(data,ipInfo)
         

            #some other IP packet like IGMP
            else :
                print 'Packet - Protocol other than TCP/UDP/ICMP'

# Main function
#@profile
def main():

    logging.basicConfig(filename='logs/sipLocator.log', level=logging.INFO, format='%(asctime)s.%(msecs).03d %(levelname)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S')   
    logging.info("-----------------------------------------------Initializing sipLocator server-----------------------------------------------")
    print "-----------------------------------------------Initializing sipLocator server-----------------------------------------------"
    
    try:
        initPacketCapture()
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
