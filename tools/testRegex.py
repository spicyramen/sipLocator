import socket,sys,logging,traceback,re,urllib,ast,os,binascii

Line = 'From: "John Doe" <sip:+14082186575@ramennetworks.com>;tag=pPK3KrZAdsq76NE8tNxW'
Line2 = 'To: "John Doe" <sip:+14082186575@ramennetworks.com>'    

def processSipMsgReqUri():
    #sip:test@video.att.com
    #sip:1.1.1.1
    #sip:test@video.att.com:5060
    #|\w+\s+(sip:.*:\d+)\sSIP/2.0|\w+\s+(sip:.*)\sSIP/2.0
    #Message = re.search(r'\w+\s+(sip:.*\@.*:\d+).*|\w+\s+(sip:.*\@.*)\sSIP/2.0.*|\w+\s+(sip:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\sSIP/2.0.*|\w+\s+(sip:.*:\d+)\sSIP/2.0', sipLine)

    try:
        reqUri = ''
        sipLine = 'INVITE sip:172.31.46.56 SIP/2.0'
        Message = re.search(r'\w+\s+(sip:.*)\sSIP/2.0|\w+\s+(sip:.*\@.*:\d+).*|\w+\s+(sip:.*\@.*)\sSIP/2.0.*', sipLine)
        if Message:
            reqUri = Message.group(1)
            print reqUri
        else:
            reqUri = '-'
    except Exception,e:
        self.containsError = True
        print traceback.format_exc()
        print e


def processSipMsgStatusCode(self):
        #sip:test@video.att.com
        #sip:test@video.att.com:5060
        try:
            sipLine = self.getSipMsgMethod()
            codeRegex  = r"^SIP/2.0\s(\d{3})\s(.*)"
            Message = re.search(r'(\w+\s+sip:.*)|(^SIP/2.0\s.*)',sipLine)
            if Message:
                statusLine = re.search(codeRegex,Message(0))
                if statusLine:
                    print "Found Status Code: " + statusLine.group(1) + ' Method: ' + statusLine.group(2)
                    logging.info("Found Status Code: " + statusLine.group(1) + ' Method: ' + statusLine.group(2))
                    self.status = statusLine.group(1)                    
            else:
                self.status = '-'
        except Exception,e:
            self.status = '?'
            self.containsError = True
            print traceback.format_exc()
            print e
def processSipMsgToTag():
    toTag = ''
    try:
        header = ' "John Doe"<sip:+14082186575@ramennetworks.com>'
        if header !='' and header!=None:
            toTagRegex = r".*;tag=(.*)"
            Message = re.search(toTagRegex,header)
            if Message:
                toTag = Message.group(1)
            else:
                toTag = '-'
                print "No To Tag Found"
        else:
            print "No To Header Found"
            toTag = '?'
        print toTag
    except Exception,e:
        print traceback.format_exc()
        print e

def validateRegex(sipLine):
    toUriRegex = r"To:.*<(sip:.*)>.*"
    toTagRegex = r"To.*;tag=(.*)"
    codeRegex  = r"^SIP/2.0\s(\d{3})\s(.*)"
    try:
    	Message = re.search(codeRegex,sipLine)
    	if Message:
    	   print "Found Status Code: " + Message.group(1) + ' Method: ' + Message.group(2)
    	else:
    	   print "No Tag Found"
    except Exception,e:
        print 'Exception'
        print e

def validateEmail(email):
	Message = re.match(r'^sip:\+?\b[\w.-]+@[\w.-]+.\w{2,4}\b', email)
	if Message:
            return True
        else:
            return False

#Message = re.search(r'(\w+\s+sip:.*)|(^SIP/2.0\s.*)', sipLine)
# ^sip:.*\@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$:\d+$|^sip:.*\@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$

def validSipUri(sipLine):
    try:
        Message = re.match(r'^sip:.*\@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$:\d{1,5}$|^sip:.*\@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^sip:\+?[\w.-]+@[\w.-]+.\w{2,4}',sipLine)
        if Message:
            return True
        else:
            return False
    except:
        return False

processSipMsgReqUri()
validateRegex('SIP/2.0 404 Not Found')
sipUri = 'sip:1@1.1.1.1'
if validSipUri(sipUri):
	print 'validSipUri: ' + sipUri
