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
from bs4 import BeautifulSoup
import gzip

kill = False
banned_list = set(['104.130.42.129'])

def int_handler(signum, frame):
    print "Exiting..."
    kill = True

signal.signal(signal.SIGINT, int_handler)

def get_headers_dict(text):
    '''
    Get a dictionary with the headers of the HTML message.
    '''
    try:
        request_line, headers_alone = text.split('\r\n', 1)
    except ValueError:
        return None
    headers = Message(StringIO(headers_alone))
    return headers

def get_host(text):
    '''
    Parse HTTP header and extract host. Use the Host field, or the Location
    field in case it is a 301 Moved resource.
    '''
    headers = get_headers_dict(text)
    if 'Host' in headers:
        return headers['Host']
    elif 'Location' in headers:
        return headers['Location']
    else:
        return None

def receive_from(sock):
    '''
    Receive data from socket.
    '''
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
    
def is_banned(ip):
    global banned_list
    if ip in banned_list:
        print 'IP %s IS BANNED!!!!!!!!!!' % ip
        return True
    else:
        return False
        
def delete_field(field, text):
    if '\r\n\r\n' in text:
        headers, body = text.split('\r\n\r\n')
    else:
        headers = text
        body = ''
    good_headers = filter(lambda x: field + ':' not in x,
                          headers.split('\n'))
    return '\n'.join(good_headers) + '\r\n\r\n' + body

        
def inject_warning(response):
    '''
    Injects a JavaScript alert on top of the page, if it is an HTML.
    '''
    headers = get_headers_dict(response)
    
    # If it is not html, we cannot inject anything
    if 'text/html' not in headers['Content-Type']:
        print 'This is not HTML, this is a %s' % headers['Content-Type']
        return response
        
    # Do the injection
    alert_msg = 'This IP address is banned. Please proceed carefully'
    i_msg = response.replace('<head>',
                              '<head>\r\n<script>alert("%s");</script>\r\n' \
                             % alert_msg,
                              1)

    return i_msg
    # import pdb; pdb.set_trace()

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
    
        # Create socket to send request to remote host
        s2_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s2_socket.settimeout(2)
    
        # Connect to host and send data
        s2_socket.connect((host, 80))
        print 'Sending message to host %s, ip %s' % (host, dst_ip)
        
        # Tamper the headers. We do not want an encoded response
        request = delete_field('Accept-Encoding', request)
        
        # Send the request
        s2_socket.sendall(request)
    
        # Receive response from host
        try:
            response = receive_from(s2_socket)
        except socket.timeout:
            print 'Received response'
            
        # Inject warning in HTML if the IP is not trusted
        if is_banned(dst_ip):
            w_response = inject_warning(response)
        else:
            w_response = response
            
        # pp = pprint.PrettyPrinter()
        # pp.pprint(response)

        # Forward response to client
        c_socket.sendall(w_response)


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
