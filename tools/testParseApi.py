import socket, sys,logging,traceback,re,urllib
from parse_rest.connection import register
from parse_rest.datatypes import Object,GeoPoint
from threading import Thread
from struct import *
import ast
#import psutil
#from memory_profiler import profile

sys.excepthook = lambda *args: None

#Obtain geoLocation
def processGeoLocation(srcIP):
    try:
        response = urllib.urlopen('http://freegeoip.net/json/' + srcIP ).read()
        geoLocationInfo = response.splitlines()
        return geoLocationInfo
    except Exception,e:
        print 'processGeoLocation() Error'

def test():
	geoLocationInfo = processGeoLocation("1.1.1.1")
	geoPoint = ast.literal_eval(geoLocationInfo[0])
	geoLocationPoint = []
	geoLocationPoint.append(geoPoint['latitude'])
	geoLocationPoint.append(geoPoint['longitude'])
	print geoLocationPoint[0]
	print geoLocationPoint[1]

def main():
    try:
    	test()
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