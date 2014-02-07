import socket,sys,logging,traceback,re,urllib,ast,os,binascii

SIP_PROXY_TAG = 'ws-src-ip'
sipHeaderInfo    = {}

def validIpAddress(address):
    try: 
        socket.inet_aton(address)
        return True
    except:
        return False

def addSipHeader(header,value):      
        sipHeaderInfo.update({header: value})
        print 'addSipHeader() ' + 'Header: ' + header + ' Value: ' + value


addSipHeader("Contact","""\"Gonzalo Gasca Meza" <sip:+14082186575@172.31.32.194:5060;rtcweb-breaker=yes;transport=tcp;ws-src-ip=98.210.160.181;ws-src-port=54588;ws-src-proto=ws>;expires=200;click2call=no;+g.oma.sip-im;+audio;language="en,fr\"""")
addSipHeader("Call-ID","e697a774-108f-e580-c05c-e753be9b4c95") 
my_regex = r".*;" + re.escape(SIP_PROXY_TAG) + r"=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3});.*"
Message = re.search(my_regex, sipHeaderInfo.get("Contact"))
if validIpAddress(Message.group(1)):
	print "IP Address: " + Message.group(1)
else:
	print "Invalid IP Address"	