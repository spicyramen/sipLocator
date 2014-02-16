TODO: WebSockets support
TODO: SIP TLS support
TODO: SIP UDP fragmentation


sipLocator
==========
Read SIP Packets from Network card (TCP,UDP)

a) stores information in Cloud.(parse.com) 
b) send SMS notification for new calls (twilio client)
c) implements RFC 6872 SIP CLF
d) Starts an XML-RPC server to retrieve data
  via XML RPC method calculates Distance from System to Call using harvesine Formula

Install:

1) apt-get install python-pip

2) If you want to send information to parse.com
  pip install git+https://github.com/dgrtwo/ParsePy.git
	a)  Change sipLocatorConfig to:
		ENABLE_PARSE=True


3) If you want to receive SMS Notifications install twilio library
   pip install twilio
	a)  Change sipLocatorConfig to:
		ENABLE_SMS_NOTIFICATIONS = True

4) If you want to generate SIP CLF record
	a)  Change sipLocatorConfig to:
		ENABLE_SIPCLF = True

5) Run python sipLocator.py


sipLocator XML server
----------------------------
1) Edit sipLocatorConfig.py

        XML_GEO_LOCATION
        XML_GEO_SEARCH_ENABLED
	
	XML_HOSTNAME
	XML_PORT
	XML_USERNAME
	XML_PASSWORD

2) Run python sipLocatorXmlRpc.py

