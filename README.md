sipLocator
==========
Read SIP Packets from Network card and stores information in Cloud. 
Starts an XML-RPC server to retrieve data
via XML RPC method calculates Distance from System to Call using harvesine Formula

Install:

1) apt-get install python-pip
2) pip install git+https://github.com/dgrtwo/ParsePy.git
3) Edit sipLocatorConfig.py
	
	XML_GEO_LOCATION
	XML_GEO_SEARCH_ENABLED

4) Run python sipLocator.py

XML server
----------------------------
1) Edit sipLocatorConfig.py
	
	XML_HOSTNAME
	XML_PORT
	XML_USERNAME
	XML_PASSWORD

2) Run python sipLocatorXmlRpc.py

TODO: WebSockets support
