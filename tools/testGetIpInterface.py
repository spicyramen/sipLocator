import socket
ip_address = ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1])
print ip_address
print len(ip_address)
print ip_address[0]

