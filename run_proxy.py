#!/usr/bin/env python2
'''
Runs a proxy on localhost. Right now it only replicates traffic.
'''

import sys
import socket
import threading
import pprint
from StringIO import StringIO
from mimetools import Message
import signal

kill = False

def int_handler(signum, frame):
    print "Exiting..."
    kill = True

signal.signal(signal.SIGINT, int_handler)

def get_host(text):
    '''
    Parse HTTP header and extract host. Also extract Location in case of 
    redirection 301
    '''
    try:
        request_line, headers_alone = text.split('\r\n', 1)
    except ValueError:
        return None
    headers = Message(StringIO(headers_alone))
    if 'Host' in headers:
        return headers['Host']
    elif 'Location' in headers:
        return headers['Location']
    else:
        return None

def receive_from(sock):
    global kill
    buff = ''
    while True and not kill:
        try:
            new_data = sock.recv(4096)
        except socket.timeout:
            return buff
        if not new_data:
            break
        buff += new_data
    return buff

def proxy_handler(c_socket, c_host, c_port):
    global kill
    while True and not kill:
        request = receive_from(c_socket)
        
        if not request:
            continue

        print '[*] Received %d bytes' % len(request)
        # Extract the host and make dns query
        host = get_host(request)
        print 'Extracted host %s' % host
        if host:
            dst_ip = socket.gethostbyname(host)
        else:
            sys.stderr.write('Could not extract host from request. Aborting...\n')
            exit(1)

        print 'Extracted IP %s from host %s' % (dst_ip, host)
    
        # Create socket to sent request to remote host
        s2_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s2_socket.settimeout(2)
    
        # Connect to host and send data
        s2_socket.connect((host, 80))
        print 'Sending message to host %s, ip %s' % (host, dst_ip)
        s2_socket.sendall(request)
    
        # Receive response from host
        try:
            response = receive_from(s2_socket)
        except socket.timeout:
            print 'Received response'
            
        pp = pprint.PrettyPrinter()
        pp.pprint(response)
    
        # Forward response to client
        c_socket.sendall(response)


if __name__=='__main__':
    '''
    Open proxy on localhost
    '''
    # Create OS socket
    s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to listen to HTTP on localhost
    s_socket.bind(('localhost', 80))

    # 20 clients allowed (NOTE: they might be from the same browser)
    s_socket.listen(20)

    # Receive connection
    while True:
        c_socket, addr = s_socket.accept()
        c_socket.settimeout(2)
        print '[*] Received connection from %s:%d' % (addr[0], addr[1])
    
        proxy_thread = threading.Thread(target=proxy_handler,
                                        args=(c_socket, addr[0], addr[1]))
    
        proxy_thread.start()
