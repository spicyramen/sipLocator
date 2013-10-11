import sipLocatorConfig
import socket, sys,traceback,re,urllib
from parse_rest.connection import register
from parse_rest.datatypes import Object
from struct import *
sys.excepthook = lambda *args: None

register(sipLocatorConfig.APPLICATION_ID, sipLocatorConfig.REST_API_KEY)

class sipCall(Object):
    try:
        def __init__(self, **kwargs):
            logging.info("sipCall() New sipCall object created()")
            print 'sipCall() New sipCall object created()'
            self.sipCallID = kwargs
            self.sipCallGeoLocation = GeoPoint(latitude=0.0, longitude=0.0)
            assert "sipCallID" in kwargs
            Object.__init__(self, **kwargs)
    except Exception:
        print traceback.format_exc()

    def setCallId(self,msg):
        self.sipCallID = msg
 
    def getSipCallId(self): 
        return self.sipCallID

def sipCallFromParse():
    try:
        testSipCall = sipCall()
        testSipCall.sipCallID = "FFFFF-7b66-4162-a2bd-d7270337d70b"
        testSipCall.save()
        hello = testSipCall.Query.get(sipCallID="d249b6ae-7b66-4162-a2bd-d7270337d70b")
        print type(hello)
        print hello.sipCallGeoLocation
    except Exception,e:
        print traceback.format_exc()
        print 'sipCallFromParse() Error'

class testClass(Object):
    """Create a Test Class Object"""
    try:
        def __init__(self, **kwargs):
            print 'testClass() New testClass object created()'
            self.testId = kwargs
            assert "testId" in kwargs
            Object.__init__(self, **kwargs)
    except Exception:
        print traceback.format_exc()
    
def testClassFromParse():
    try:
    	testObj = testClass(testId="GGGGG-7b66-4162-a2bd-d7270337d70b")
    	testObj.save()
    	bye = testClass.Query.get(objectId="AlgpLvyoJH")
    	print type(bye)
        print bye.testId
    except Exception,e:
        print traceback.format_exc()
        print 'testClassFromParse() Error'

def main():

    print "-----------------------------------------------Initializing sipLocator server-----------------------------------------------"
    
    try:
    	testClassFromParse()
        sipCallFromParse()
    except KeyboardInterrupt:
        try:
            sys.stdout.close()
        except:
            pass
        try:
            sys.stderr.close()
        except:
            pass
    except Exception,e:
        print 'Exception found'
        print traceback.format_exc()
    except (IOError, OSError):
       pass
        
if __name__ == '__main__':
    main()        
