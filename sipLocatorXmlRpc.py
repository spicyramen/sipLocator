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
import math
from SimpleXMLRPCServer import SimpleXMLRPCServer
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler
from parse_rest.connection import register
from parse_rest.datatypes import Object,GeoPoint
from parse_rest.query import Queryset
from parse_rest.query import QueryResourceDoesNotExist
from struct import *

sys.excepthook = lambda *args: None

register(sipLocatorConfig.APPLICATION_ID, sipLocatorConfig.REST_API_KEY)

systemErrors = {
    1: 'Method not supported',
    2: 'Duplicate callID',
    4: 'No such callID',
    5: 'No such message',
    6: 'Too many calls.',
    7: 'Too many messages.',
    8: 'No callID supplied',
    10: 'No geoLocation supplied',
    13: 'GeoLocation search not enabled',
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
        print 'sipCall() __init__ error'
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
        def __init__(self, **kwargs):
            logging.info("sipMessage() __init__ sipMessage")
            print 'sipMessage() __init__ sipMessage'
            self.hasSDP             = False
            self.sipHeaderInfo      = {}
            self.sipMsgSdpInfo      = {}            
            self.sipMsgMethodInfo   = ''
            self.sipMsgCallId       = ''
            self.sipMsgCallId = kwargs
            assert "sipMsgCallId" in kwargs
            Object.__init__(self, **kwargs)
    except Exception:
        print 'sipMessage() __init__ error'
        print traceback.format_exc()

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

#Connects to Parse using parse_rest
#https://github.com/dgrtwo/ParsePy
def getSipCallFromParse(sipCallParam):
    try:
        print 'getSipCallFromParse() Contacting Parse CallID: ' + sipCallParam

        parseSipCall = sipCall.Query.get(sipCallID=sipCallParam)
        print type(parseSipCall)
        if parseSipCall!=None:
            print 'getSipCallFromParse() Found call online!'
            logInfo('getSipCallFromParse() Found call online!')
            logInfo(parseSipCall.sipCallID)
            logInfo(parseSipCall.sipCallGeoPoint)
            logInfo(parseSipCall.sipCallGeoLocation)
            return parseSipCall
        else:
            return None
    except QueryResourceDoesNotExist:
        print 'QueryResourceDoesNotExist Call not found'
        return 4
    except Exception,e:
        print traceback.format_exc()
        return None


def getSipMessageFromParse(sipMsgParam):
    try:
        print 'getSipMessageFromParse() Contacting Parse to find message using sipMsgCallID: ' + sipMsgParam + ' API get.sipmessage'
        parseSipMessages = sipMessage.Query.all().filter(sipMsgCallId=sipMsgParam)
        print type(parseSipMessages)
        print 'getSipMessageFromParse() SIP Messages found in Parse (' + str(parseSipMessages.count()) + ') API get.sipmessage'
        logInfo('getSipMessageFromParse() SIP Messages found in Parse (' + str(parseSipMessages.count()) + ') API get.sipmessage')
        if parseSipMessages.count() > sipLocatorConfig.XML_SIP_MESSAGE_LIMIT:
            return 7
        elif parseSipMessages.count()==0:
            return 5
        elif parseSipMessages!=None:
            return parseSipMessages    
        else:
            return None
    except QueryResourceDoesNotExist:
        print 'QueryResourceDoesNotExist Message not found'
        return 5
    except Exception,e:
        print traceback.format_exc()
        return None


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
def processSipXmlParameters(msg,type):
    xmlResponse = []
    struct = []
    member = {}
    params = copy.deepcopy(msg)
    callID = ''
    getSDP = False
    getHeaders = False
    getIP = False
    hasSDP = False
    print msg

    #  Optional
    # 'getSDP'    :True
    # 'getHeaders':True
    # 'getIP'     :True

    # Verify authentication and then collect other parameters
    if type==sipLocatorConfig.XML_SIP_MESSAGE:

        for element in params:
            if element == 'sipMsgCallID':
                callID = params.get('sipMsgCallID')
            if element == 'getSDP':
                getSDP = params.get('getSDP') 
            if element == 'getHeaders':
                getHeaders = params.get('getHeaders') 
            if element == 'getIP':
                getIP = params.get('getIP') 
            if element == 'hasSDP':
                hasSDP = params.get('hasSDP')

        if len(callID)>256 and not isinstance(callID, str):
            xmlResponse.append(16)
            return xmlResponse

        # Verify param is Found
        if len(callID) != 0:
            #QuerySet of SIP Message Objects
            parseSipMessages = getSipMessageFromParse(callID)
        else:
            xmlResponse.append(16)
            return xmlResponse

         # Call message found in Parse
        if parseSipMessages==5:
            xmlResponse.append(5)
            return xmlResponse
        elif parseSipMessages==7:
            xmlResponse.append(7)
            return xmlResponse
        elif parseSipMessages==None:
            xmlResponse.append(-1)
            return xmlResponse
        else:
            print 'processSipXmlParameters() Processing SIP Messages found API get.sipmessage'
            logInfo('processSipXmlParameters() Processing SIP Messages found API get.sipmessage')

            for parseSipMsg in parseSipMessages:
                
                member['sipMsgCallId'] = parseSipMsg.sipMsgCallId
                member['sipMsgMethodInfo'] = parseSipMsg.sipMsgMethodInfo
                # Filters
                if getSDP:
                    if parseSipMsg.hasSDP:    
                        member['sipMsgSdpInfo'] = parseSipMsg.getSdpInfo()
                    else:
                        member['sipMsgSdpInfo'] = []
                if getHeaders:
                    member['sipHeaderInfo'] = parseSipMsg.getSipHeaders()
                if getIP:
                    member['sipMsgIpInfo']  = parseSipMsg.getSipMsgIpInfo()
                # Add call to XML Response
                xmlResponse.append(member)
                member = {}
            return xmlResponse

    elif type==sipLocatorConfig.XML_SIP_CALL:
        for element in params:
            if element == 'sipCallID':
                callID = params.get('sipCallID')       

        if len(callID)>256 and not isinstance(callID, str):
            xmlResponse.append(16)
            return xmlResponse

        # Gets Parse Object
        # Verify param is Found
        if len(callID) != 0:
            parseSipCall = getSipCallFromParse(callID)
        else:
            xmlResponse.append(16)
            return xmlResponse

        # Call not found in Parse
        if parseSipCall==4:
            xmlResponse.append(4)
            return xmlResponse
        elif parseSipCall==None:
            xmlResponse.append(-1)
            return xmlResponse
        else:
            xmlResponse.append(parseSipCall.sipCallID)
            xmlResponse.append(parseSipCall.sipCallGeoPoint)
            if (xmlResponse !=-1 and len(xmlResponse) >= 2):
                print "processSipXmlParameters() API get.sipcall Call-ID found: " + xmlResponse[0]
                logInfo(xmlResponse)
                xmlResponse = {'sipCallID' :xmlResponse[0],'sipCallGeoPoint':xmlResponse[1]}
                return xmlResponse
            else:
                xmlResponse.append(-1)
                return xmlResponse

    elif type==sipLocatorConfig.XML_SIP_GEOLOCATION:

        for element in params:
            if element == 'sipCallID':
                callID = params.get('sipCallID')

        if len(callID)>256 and not isinstance(callID, str):
            xmlResponse.append(16)
            return xmlResponse

        # Gets Parse Object
        # Verify param is Found
        if len(callID)!=0:
            parseSipCall = getSipCallFromParse(callID)
        else:
            xmlResponse.append(16)
            return xmlResponse

        # Call not found in Parse
        if parseSipCall==4:
            xmlResponse.append(4)
            return xmlResponse
        # Nothing is return
        elif parseSipCall == None:
            xmlResponse.append(-1)
            return xmlResponse
        else:
            location = parseSipCall.sipCallGeoPoint
            print 'sipCall latitude : ' +  str(location.latitude)
            print 'sipCall longitude: ' +  str(location.longitude)

            sipCallLatitude = location.latitude
            sipCallLongitude = location.longitude
            systemLatitude = sipLocatorConfig.XML_GEO_LOCATION.get('latitude')
            systemLongitude = sipLocatorConfig.XML_GEO_LOCATION.get('longitude')

            if sipCallLongitude!=None and sipCallLatitude!=None:
                distance = haversineDistance((sipCallLatitude,sipCallLongitude),(systemLatitude,systemLongitude))
                xmlResponse.append(parseSipCall.sipCallID)
                xmlResponse.append(round(distance,2))
            else:
                xmlResponse.append(-1)
                return xmlResponse
        try:   
            if (xmlResponse !=-1 and len(xmlResponse) >= 2):
                print "processSipXmlParameters() API get.sipcallgeolocation Call-ID found: " + xmlResponse[0]
                print "processSipXmlParameters() API get.sipcallgeolocation Distance: " + str(xmlResponse[1])
                logInfo(xmlResponse)
                xmlResponse = {'sipCallID' :xmlResponse[0],'sipCallDistance':xmlResponse[1]}
                return xmlResponse
            else:
                xmlResponse.append(-1)
                return xmlResponse        
        except Exception:
            print traceback.format_exc()
            return fault_code(systemErrors[34],34) 

    else:
        return fault_code(systemErrors[34],34)          

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
        xmlResponse = processSipXmlParameters(params,sipLocatorConfig.XML_SIP_MESSAGE)
        if 5 in xmlResponse:
            return fault_code(systemErrors[5],5)
        if 7 in xmlResponse:
            return fault_code(systemErrors[7],7)    
        if -1 in xmlResponse:
            return fault_code(systemErrors[201],201)
        else:
            logInfo(xmlResponse)
            return xmlResponse

#API Method insert.sipmessage
def insertSipMessage(msg):
    print("insertSipMessage() API insertSipMessage")
    logInfo("insertSipMessage() API insertSipMessage")

#API Method get.sipcall
def getSipCall(msg):
    print("getSipCall() API get.sipcall")
    logInfo("getSipCall() API get.sipcall")
    params = xmlRequestHandler(msg)
    if (params == 34):
        return fault_code(systemErrors[34],34)
    elif(params == 101):
        return fault_code(systemErrors[101],101)
    else:
        xmlResponse = processSipXmlParameters(params,sipLocatorConfig.XML_SIP_CALL)
        if 4 in xmlResponse:
            return fault_code(systemErrors[4],4)
        elif 16 in xmlResponse:
            return fault_code(systemErrors[16],16)    
        elif -1 in xmlResponse:
            return fault_code(systemErrors[201],201)
        else:
            logInfo(xmlResponse)
            return xmlResponse

#API Method insert.sipcall
def insertSipCall(msg):
    print("insertSipCall() API insertSipCall")
    logInfo("insertSipCall() API insertSipCall")

def getSipCallGeoLocation(msg):
    print("getSipCallGeoLocation() API get.sipcallgeolocation")
    logInfo("getSipCallGeoLocation() API get.sipcallgeolocation")
    params = xmlRequestHandler(msg)
    if (params == 34):
        return fault_code(systemErrors[34],34)
    elif(params == 101):
        return fault_code(systemErrors[101],101)
    else:
        if sipLocatorConfig.XML_GEO_SEARCH_ENABLED:
            xmlResponse = processSipXmlParameters(params,sipLocatorConfig.XML_SIP_GEOLOCATION)
            if 4 in xmlResponse:
                return fault_code(systemErrors[4],4)
            elif 16 in xmlResponse:
                return fault_code(systemErrors[16],16)    
            elif -1 in xmlResponse:
                return fault_code(systemErrors[201],201)
            else:
                logInfo(xmlResponse)
                return xmlResponse
        else:
            return fault_code(systemErrors[13],13)

    # Calculate the Distance
def haversineDistance(location1, location2):
    print 'haversineDistance()'
    """Method to calculate Distance between two sets of Lat/Lon."""
    #http://en.wikipedia.org/wiki/Haversine_formula

    lat1, lon1 = location1
    lat2, lon2 = location2
    earth = 6371 #Earth's Radius in Kms.

     #Calculate Distance based in Haversine Formula
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2) * math.sin(dlat/2) + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2) * math.sin(dlon/2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    d = earth * c
    if sipLocatorConfig.XML_GEO_SEARCH_MILES:
        return d * 0.62137
    else:
        return d

def fault_code(string,code):
    xmlResponse = {'faultCode' :code,'faultString':string }
    logInfo(xmlResponse)
    return xmlResponse

# Register an instance; all the methods of the instance are published as XML-RPC methods (in this case, just 'div').
class Methods:
        def getVersion(self):
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

