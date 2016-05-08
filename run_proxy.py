#!/usr/bin/env python2
'''
Runs a proxy on localhost. Right now it only replicates traffic.
'''

import sys
import socket
import threading
import pprint

def receive_from(sock):
    sock.settimeout(2)
    buff = ''
    while(True):
        try:
            new_data = sock.recv(4096)
        except socket.timeout:
            return buff
        # import pdb; pdb.set_trace()
        if not new_data:
            break
        buff += new_data
    return buff


def proxy_handler(c_socket, c_host, c_port):
    local_buffer = receive_from(c_socket)
    print '[*] Received %d bytes' % len(local_buffer)
    
    pp = pprint.PrettyPrinter()
    pp.pprint(local_buffer)
    

if __name__=='__main__':
    '''
    Open proxy on localhost
    '''
    # Create OS socket
    s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to listen to HTTP on localhost
    s_socket.bind(('localhost', 80))

    # Only 1 client connection allowed
    s_socket.listen(1)

    # Receive connection
    c_socket, addr = s_socket.accept()
    print '[*] Received connection from %s:%d' % (addr[0], addr[1])

    proxy_thread = threading.Thread(target=proxy_handler,
                                    args=(c_socket, addr[0], addr[1]))

    proxy_thread.start()
