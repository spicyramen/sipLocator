import xmlrpclib
import requests

'''
@author Gonzalo Gasca Meza
		AT&T Labs 
		Date: June 2013
		Call XML RPC Parse
'''

hostname = '192.168.182.130'
port     = '8081'
url      = 'http://' + hostname + ':' + port + '/RPC2'
username = "sut"
password = "1qaz2wsx"

xmlRpcClient = xmlrpclib.ServerProxy(url,verbose=True,encoding='UTF-8')

def ping(msg):
  print xmlRpcClient.ping(msg)

def get_version():
  print xmlRpcClient.getVersion()


def get_sipcall(sipCallID):
  if len(sipCallID)>256 and not isinstance(sipCallID, str):
      return
  parameters = {'sipCallID' :sipCallID,'authenticationUser':username,'authenticationPassword':password}
  params = tuple([parameters])
  xmlrpccall = xmlrpclib.dumps(params,'get.sipcall',encoding='UTF-8')
  response = requests.request( 'POST', url,
                             data = xmlrpccall,
                             headers = { 'Content-Type': 'application/xml' },
                             timeout = 100, 
                             stream = False, )
  if response.status_code == 200:
    result = xmlrpclib.loads( response.content, )[ 0 ]
    print result
  else:
    print '(sipCallID) Error'
    return -1

def get_sipmessage(sipCallID):

  if len(sipCallID)>256 and not isinstance(sipCallID, str):
      return

  #  Optional
  # 'getSDP'    :True
  # 'getHeaders':True
  # 'getIP'     :True
  parameters = {'sipMsgCallID' :sipCallID,'getSDP':True,'authenticationUser':username,'authenticationPassword':password}
  params = tuple([parameters])
  xmlrpccall = xmlrpclib.dumps(params,'get.sipmessage',encoding='UTF-8')
  response = requests.request( 'POST', url,
                             data = xmlrpccall,
                             headers = { 'Content-Type': 'application/xml' },
                             timeout = 100, 
                             stream = False, )
  if response.status_code == 200:
    result = xmlrpclib.loads( response.content, )[ 0 ]
    print result
  else:
    print '(sipCallID) Error'
    return -1


def get_sipgeolocation(sipCallID):
  if len(sipCallID)>256 and not isinstance(sipCallID, str):
      return
  parameters = {'sipCallID' :sipCallID,'authenticationUser':username,'authenticationPassword':password}
  params = tuple([parameters])
  xmlrpccall = xmlrpclib.dumps(params,'get.sipcallgeolocation',encoding='UTF-8')
  response = requests.request( 'POST', url,
                             data = xmlrpccall,
                             headers = { 'Content-Type': 'application/xml' },
                             timeout = 100, 
                             stream = False, )
  if response.status_code == 200:
    result = xmlrpclib.loads( response.content, )[ 0 ]
    print result
  else:
    print '(sipCallID) Error'
    return -1

# Print list of available methods
def list_methods():
  print xmlRpcClient.system.listMethods()

try:
    ping("request")
    get_sipcall('86c3c1ac9-6d5d-4d55-ab21-f90e4cfa87f0')
    get_sipmessage('6c3c1ac9-6d5d-4d55-ab21-f90e4cfa87f0')
    get_version()
    get_sipgeolocation('a286eed2-99c0-4a71-9245-5a48360eaa41')
    #conference_create("AT&T TelePresence")
    #conference_enumerate()
    #conference_status("rqdor4jk-aho7-9rap-hodd-je5pbt2ulypp")
except Exception as err:
    print("A fault occurred!")
    print "%s" % err
