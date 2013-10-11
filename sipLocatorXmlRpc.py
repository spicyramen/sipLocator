'''
@author Gonzalo Gasca Meza
        AT&T Labs 
        Date: September 2013
        Purpose: Serves as XMLRPC server to provide Read Call Info, insert Call info
'''

import sipLocatorConfig
import socket, sys,logging,traceback,re,urllib
import threading
import thread
import copy
from SimpleXMLRPCServer import SimpleXMLRPCServer
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler
from parse_rest.connection import register
from parse_rest.datatypes import Object
from struct import *
sys.excepthook = lambda *args: None

register(sipLocatorConfig.APPLICATION_ID, sipLocatorConfig.REST_API_KEY)

systemErrors = {
    1: 'Method not supported',
    2: 'Duplicate callID',
    4: 'No such callID',
    5: 'No such message',
    6: 'Too many calls.',
    8: 'No callID supplied',
    10: 'No geoLocation supplied',
    13: 'Invalid PIN specified',
    15: 'Insufficient privileges',
    16: 'Invalid callID value',
    17: 'Call reservation failure',
    18: 'Duplicate numeric ID',
    20: 'Unsupported participant type',
    25: 'New limit lower than currently active',
    34: 'Internal error',
    35: 'String is too long',
    101:'Missing parameter',
    102:'Invalid parameter',
    103:'Malformed parameter',
    105:'Request too large',
    201:'Operation failed',
    202:'Product needs its activation feature key',
    203:'Too many asynchronous requests'
}

###########################################################################################
#Connects to Parse using parse_rest https://github.com/dgrtwo/ParsePy
###########################################################################################

class sipCall(Object):
    """Create a SIP Call Object"""
    try:
        #http://stackoverflow.com/questions/19292220/python-parse-module-error-when-doing-query-filter-or-query-get
        def __init__(self, **kwargs):
            logging.info("sipCall() New sipCall object created()")
            print 'sipCall() New sipCall object created()'
            self.sipCallID = kwargs
            assert "sipCallID" in kwargs
            Object.__init__(self, **kwargs)
    except Exception:
        print traceback.format_exc()

    def setCallId(self,param):
        self.sipCallID = param
 
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
    try:
        def __init__(self):
            logging.info("sipMessage() New sipMessage object created()")
            print 'sipMessage() New sipMessage object created()'
            self.__sipHeaderInfo    = {}
            self.__sipSdpInfo       = {}
            self.sipMsgGeoLocation  = {}
            self.sipMessageInfo     = ''
            self.sipSdpList         = []
            self.sipHeaderList      = []
            self.hasSDP              = False
    except Exception:
        print traceback.format_exc()

    def setSipMessage(self,msg):
        self.sipMessageInfo = msg
  
    def getSipMsgMethod(self):
        return self.sipMessageInfo

    def addSipHeader(self,header,value):      
        self.__sipHeaderInfo.update({header: value})
        print header + ' ' + value
        #print 'sipMessage() addHeader ' + 'Header: ' + header + ' Value: ' + value
    
    def addSdpInfo(self,sdpKey,sdpValue):      
        self.__sipSdpInfo.update({sdpKey: sdpValue})
        print sdpKey + '=' + sdpValue
        #print 'sipMessage() addHeader ' + 'Header: ' + header + ' Value: ' + value

    def getSdpInfo(self):
        self.sipSdpList = []
        # Python 3.x Feature Convert a Python dictionary to a list of tuples
        # http://stackoverflow.com/questions/674519/how-can-i-convert-a-python-dictionary-to-a-list-of-tuples
        self.sipSdpList = [(key,value) for (key,value) in self.__sipSdpInfo.iteritems()]
        return self.sipSdpList

    def getSipHeaders(self):
        self.sipHeaderList = []
        # Python 3.x Feature Convert a Python dictionary to a list of tuples
        # http://stackoverflow.com/questions/674519/how-can-i-convert-a-python-dictionary-to-a-list-of-tuples
        self.sipHeaderList = [(key,value) for (key,value) in self.__sipHeaderInfo.iteritems()]
        return self.sipHeaderList

    def getSipMsgCallId(self):
        try:
            callInfo = dict(self.sipHeaderList)
            #logger.info('getSipCallId() Sip Call-ID: ' + callInfo.get('Call-ID:'))
            return callInfo.get('Call-ID:')
        except Exception,e:
            print 'getSipMsgCallId() Error'
    
    def setSipMsgGeolocation(self,geoLocation):
        self.sipMsgGeoLocation = geoLocation

    def getSipMsgGeoLocation(self):
        return self.sipMsgGeoLocation

    def setSipMsgIpInfo(self,ipInfo):
        self.sipMsgIpInfo = ipInfo

    def getSipMsgIpInfo(self):
        return self.sipMsgIpInfo
    
    def processSipMsgSdp(self):
        try:
            callInfo = dict(self.sipHeaderList)

            sipMsgContainsMedia = callInfo.get('Content-Type:')
            if sipMsgContainsMedia is not None:
                if sipMsgContainsMedia.find('application/sdp')!=-1:
                    logging.info("processSipMsgSdp() SDP found")
                    print 'processSipMsgSdp() SDP found'
                    self.hasSDP = True
            else:
                # No SDP  
                self.hasSDP = False 
        except Exception,e:
            print 'processSipMsgSdp() Error'


###########################################################################################
# Handle XMLRequests and client login
###########################################################################################

class XmlRequestHandler(SimpleXMLRPCRequestHandler):
    # Restrict to a particular path.
    rpc_paths = ('/RPC2',)
    def do_POST(self):
        clientIP, port = self.client_address
        # Log client IP and Port
        logging.info('Client IP: %s - Port: %s' % (clientIP, port))
        try:
            data = self.rfile.read(int(self.headers["content-length"]))
            logging.info('Client request: \n%s\n' % data)
            response = self.server._marshaled_dispatch(data, getattr(self, '_dispatch', None))
            logging.info('Server response: \n%s\n' % response)
        except: # This should only happen if the module is buggy
            # internal error, report as HTTP server error
            self.send_response(500)
            self.end_headers()
            logging.error('Internal error')
        else:
            # got a valid XML RPC response
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.send_header("Content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            # shut down the connection
            self.wfile.flush()
            self.connection.shutdown(1)

# Run the server's main loop
def startXmlRpc():

    logging.info("-----------------------------------------------XML-RPC Request Handler Server started------------------------------------------------")
    print "-----------------------------------------------XML-RPC Request Handler Server started------------------------------------------------"
    logging.info("XML-RPC Hostname: " + sipLocatorConfig.XML_HOSTNAME +  " Port: " + str(sipLocatorConfig.XML_PORT))
    print "XML-RPC Hostname: " + sipLocatorConfig.XML_HOSTNAME +  " Port: " + str(sipLocatorConfig.XML_PORT)
    logging.info("XML-RPC API Version:  " + sipLocatorConfig.XML_VERSION)
    print "XML-RPC API Version:  " + sipLocatorConfig.XML_VERSION
    try:        
        logging.info("-----------------------------------------------Server packet capture started------------------------------------------------")
        threading.Thread(target=server.serve_forever()).start()
    except KeyboardInterrupt:
        print ""
        logging.info("XML-RPC Request Handler Server stopping....")
    except Exception as instance:
        print type(instance)
        print instance.args
        logging.error("startXmlRpc() Exception: " + str(instance))
        raise SystemExit

###########################################################################################
# Handle SipParse request and client login
###########################################################################################

def sipCallInsertViaParse(sipCall):
    # Connects to Parse via initial settings and created object
    try:
        sipCall.save()
        logging.info("sipCallInsertViaParse() sipCall Record created in Parse - CallID: " + sipCall.getSipCallId())
        print 'sipCallInsertViaParse() sipCall Record created in Parse - CallID: ' + sipCall.getSipCallId()
    except Exception,e:
        print 'sipCallInsertViaParse() Error'

#Connects to Parse using parse_rest
#https://github.com/dgrtwo/ParsePy
def sipMessageInsertViaParse(sipMsg):
    # Connects to Parse via initial settings and created object
    try:
        sipMsg.save()
        logging.info("sipMessageInsertViaParse() sipMessage Record created in Parse - CallID: " + sipMsg.getSipMsgMethod() + "  " + sipMsg.getSipMsgCallId())
        print 'sipMessageInsertViaParse() sipMessage Record created in Parse - CallID: ' + sipMsg.getSipMsgMethod() + ' ' + sipMsg.getSipMsgCallId()
    except Exception,e:
        print 'sipMessageInsertViaParse() Error'

def getSipMessageFromParse(sipMsgCallID):
    parseSipMessages = sipMessage.Query.filter(sipCallID=sipMsgCallID)
    return parseSipMessages

def getSipCallFromParse(sipCallParam):
    try:
        print 'getSipCallFromParse() Contacting Parse CallID: ' + sipCallParam
        parseSipCall = sipCall.Query.get(sipCallID=sipCallParam)
        print type(parseSipCall)
        if parseSipCall!=None:
            print 'getSipCallFromParse() Found call online!'
            print parseSipCall.sipCallID
            print parseSipCall.sipCallGeoPoint
            print parseSipCall.sipCallGeoLocation
            return parseSipCall
        else:
            return None
    except Exception,e:
        print traceback.format_exc()
        print 'getSipCallFromParse() Error'


# Logging info
def logInfo(msg):
    logging.info(msg)

###########################################################################################
# Handle client requests
###########################################################################################

#Verifies authentication and returns remaining parameters specified in structure
def xmlRequestHandler(msg):
    username = ""
    password = ""
    params = copy.deepcopy(msg)
    # Verify authentication and then collect other parameters
    for element in params:
        if element == 'authenticationUser':
            username = msg.get('authenticationUser')        
        if element == 'authenticationPassword':
            password = msg.get('authenticationPassword')
            
    if username == "" or password == "":
        logging.error("Invalid credentials")
        return 101      
    if (authenticationModule(username,password)):
        del params['authenticationUser']
        del params['authenticationPassword']
        return params
    else:
        return 34   

#Verify password is correct
def authenticationModule(username,password):
    if len(username)>128 or len(password)>128:
        return False
    if username == sipLocatorConfig.XML_USERNAME and password == sipLocatorConfig.XML_PASSWORD:
        return True
    else:
        return False

#Obtain parameters from XML Call
def processXmlParameters(msg,type):
    xmlResponse = []
    print msg
    params = copy.deepcopy(msg)
    callID = ''

    # Verify authentication and then collect other parameters
    if type==sipLocatorConfig.XML_SIP_MESSAGE:
        for element in params:
            if element == 'sipMsgCallID':
                callID = params.get('sipMsgCallID')  
        
        #   Add '' to callID in case is not coming like that
        #if callID.find("'")==-1:
        #    callID = "'" + callID + "'"         

        if len(callID)>80 and not isinstance(callID, str):
            return -1
        getSipMessageFromParse(callID)


    elif type==sipLocatorConfig.XML_SIP_CALL:
        for element in params:
            if element == 'sipCallID':
                callID = params.get('sipCallID')       

        if len(callID)>80 and not isinstance(callID, str):
            return -1

        # Gets Parse Object
        parseSipCall = getSipCallFromParse(callID)

        if parseSipCall!=None:
            xmlResponse.append(parseSipCall.sipCallID)
            xmlResponse.append(parseSipCall.sipCallGeoPoint)
            if (xmlResponse !=-1 and len(xmlResponse) >= 2):
                print "get_sipcall() API get.sipcall Call-ID found: " + xmlResponse[0]
                logInfo(xmlResponse)
                xmlResponse = {'sipCallID' :xmlResponse[0],'sipCallGeoPoint':xmlResponse[1]}
                return xmlResponse
            else:
                return fault_code(systemErrors[201],201)
        else:
            return fault_code(systemErrors[201],201)

        
    else:
        return -1            

###########################################################################################
# API Method implementation
###########################################################################################

def pingMethod(msg):
    logInfo("pingMethod() API ping")
    if msg == 'request':
     return 'reply'
    else:
     return 'invalid message: ' + msg

def getSipMessage(msg):
    print("getSipMessage() API get.sipmessage")
    logInfo("getSipMessage() API get.sipmessage")
    params = xmlRequestHandler(msg)
    if (params == 34):
        return fault_code(systemErrors[34],34)
    elif(params == 101):
        return fault_code(systemErrors[101],101)
    else:
        xmlResponse = processXmlParameters(params,sipLocatorConfig.XML_SIP_MESSAGE)
        if (xmlResponse!=-1):
            logInfo(xmlResponse)
            return xmlResponse
        else:
            return fault_code(systemErrors[4],4)


def insertSipMessage(msg):
    print("insertSipMessage() API insertSipMessage")
    logInfo("insertSipMessage() API insertSipMessage")

def getSipCall(msg):
    print("getSipCall() API getSipCall")
    logInfo("getSipCall() API getSipCall")
    params = xmlRequestHandler(msg)
    if (params == 34):
        return fault_code(systemErrors[34],34)
    elif(params == 101):
        return fault_code(systemErrors[101],101)
    else:
        xmlResponse = processXmlParameters(params,sipLocatorConfig.XML_SIP_CALL)
        if (xmlResponse!=-1):
            logInfo(xmlResponse)
            return xmlResponse
        else:
            return fault_code(systemErrors[4],4)

def insertSipCall(msg):
    print("insertSipCall() API insertSipCall")
    logInfo("insertSipCall() API insertSipCall")

def getSipCallGeoLocation(msg):
    print("getSipCallGeoLocation() API getSipCallGeoLocation")
    logInfo("getSipCallGeoLocation() API getSipCallGeoLocation")
    haversineDistance()

    # Calculate the Distance
def haversineDistance(location1, location2):
    """Method to calculate Distance between two sets of Lat/Lon."""
    lat1, lon1 = location1
    lat2, lon2 = location2
    earth = 6371 #Earth's Radius in Kms.

     #Calculate Distance based in Haversine Formula
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2) * math.sin(dlat/2) + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2) * math.sin(dlon/2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    d = earth * c
    return d

def fault_code(string,code):
    xmlResponse = {'faultCode' :code,'faultString':string }
    logInfo(xmlResponse)
    return xmlResponse

# Register an instance; all the methods of the instance are published as XML-RPC methods (in this case, just 'div').
class Methods:
        def show_version(self):
            print("show_version() API show.version")
            logInfo("show_version() API show.version")
            return sipLocatorConfig.XML_VERSION


###########################################################################################
# Create XMLserver
###########################################################################################

server = SimpleXMLRPCServer((sipLocatorConfig.XML_HOSTNAME, sipLocatorConfig.XML_PORT),requestHandler=XmlRequestHandler,allow_none=True,logRequests=True)
server.register_function(pingMethod, 'ping')
server.register_function(getSipMessage, 'get.sipmessage')
server.register_function(insertSipMessage, 'insert.sipmessage')
server.register_function(getSipCall, 'get.sipcall')
server.register_function(insertSipCall, 'insert.sipcall')
server.register_function(getSipCallGeoLocation, 'get.sipcallgeolocation')
server.register_instance(Methods())

# Main function
def main():

    logging.basicConfig(filename='logs/sipLocatorXML.log', level=logging.INFO, format='%(asctime)s.%(msecs).03d %(levelname)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S') 
    logging.info("-----------------------------------------------Initializing sipLocator XML server-----------------------------------------------")
    print "-----------------------------------------------Initializing sipLocator XML server-----------------------------------------------"
    
    try:
        startXmlRpc()

    except KeyboardInterrupt:
        logging.info ("sipLocator XML server stopping....")
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

