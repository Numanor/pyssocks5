# -*- coding: utf-8 -*-
import sys 
import struct
import signal
import argparse

import gevent
from gevent import socket
from gevent.server import StreamServer
from gevent.socket import create_connection, gethostbyname

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from SSocket import SSocket
from utils.socks import *

class SocksLocalServer(StreamServer):
    def __init__(self, listen, remote_ip, remote_port):
        super(SocksLocalServer, self).__init__(listen)
        self.remote_ip = remote_ip
        self.remote_port = remote_port

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.recv(1)))
        return methods
    
    def handle(self, sock, addr):
        print('connection from %s:%s' % addr)

        src = SSocket(socket=sock)

        """
            socks5 negotiation step1: choose an authentication method
        """
        ver, n_method = src.unpack('BB', 2) 
        # 1.1 socks version
        if ver != SOCKS_VERSION_V:    # SOCKS Protocol Version 5 (RFC 1928)
            src.pack('BB', SOCKS_VERSION_V, SOCKS_NO_ACCEPT_METHOD)
            return
        # 1.2 authentication method
        if n_method == 0:
            src.pack('BB', SOCKS_VERSION_V, SOCKS_NO_ACCEPT_METHOD)
            return
        else:
            methods = []
            for i in range(n_method):
                methods.append(ord(src.recv(1)))
            if SOCKS_AUTH_NONE not in set(methods): # No Authentication
                src.pack('BB', SOCKS_VERSION_V, SOCKS_NO_ACCEPT_METHOD)
                return
        # 1.3 auth method negotiation succeed
        src.pack('!BB', SOCKS_VERSION_V, SOCKS_AUTH_NONE)


        """
            socks5 negotiation step2: specify command and destination
        """
        ver, cmd, rsv, atype = src.unpack('BBBB', 4)

        # 2.1 only support 'connect' command
        if cmd != SOCKS_CMD_CONNECT:
            src.pack('BBBBIH', SOCKS_VERSION_V, SOCKS_REP_CMD_UNK, 0x00, 0x01, 0, 0)
            return

        # 2.2 only support ipv4/domain name address type
        if atype == SOCKS_ATYP_IPV4: #ipv4
            host, port = src.unpack('!IH', 6)
            hostip = socket.inet_ntoa(struct.pack('!I', host))
        elif atype == SOCKS_ATYP_DOMAIN: #domain name
            length = src.unpack('B', 1)[0]
            hostname, port = src.unpack("!%dsH" % length, length + 2)
            hostip = gethostbyname(hostname)
            host = struct.unpack("!I", socket.inet_aton(hostip))[0]
        else:
            src.pack('!BBBBIH', SOCKS_VERSION_V, SOCKS_REP_CMD_NOT, 0x00, 0x01, 0, 0)
            return
        
        # setup remote proxy
        try:
            dest = SSocket(addr = (self.remote_ip, self.remote_port))
        except IOError, ex:
            print "%s:%d" % addr, "failed to connect to %s:%d" % ("127.0.0.1", 9099)
            src.pack('!BBBBIH', 0x05, 0x03, 0x00, 0x01, host, port)
            return
        # aes set up
        aes_key = get_random_bytes(16)
        aes_iv = get_random_bytes(16)
        dest.aes_init(aes_key, AES.MODE_CBC, aes_iv)
        dest.sendall(aes_key)
        dest.sendall(aes_iv)
        # send remote host addr
        dest.aes_pack('!IH', host, port)
        # set up remote connnection
        ver, reply, _, atype, host, port = dest.aes_unpack('!BBBBIH', 10)
        if reply is SOCKS_REP_CON_SUC:
            src.pack('!BBBBIH', SOCKS_VERSION_V, SOCKS_REP_CON_SUC, 0x00, SOCKS_ATYP_IPV4, host, port)
        else:
            src.pack('!BBBBIH', SOCKS_VERSION_V, SOCKS_REP_NET_ERO, 0x00, SOCKS_ATYP_IPV4, host, port)
            return

        gevent.spawn(src.aes_enc_forward, dest)
        gevent.spawn(dest.aes_dec_forward, src)

    def close(self):
        sys.exit(0)

    @staticmethod
    def start_server(args):
        server = SocksLocalServer(('0.0.0.0', args.port), remote_ip=args.remote_ip, remote_port=args.remote_port)
        gevent.signal(signal.SIGTERM, server.close)
        gevent.signal(signal.SIGINT, server.close)
        print("Server is listening on 0.0.0.0:%d" % args.port)
        server.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', default=9011, type=int)
    parser.add_argument('--remote_ip', default="127.0.0.1")
    parser.add_argument('--remote_port', default=9099, type=int)
    args = parser.parse_args()
    SocksLocalServer.start_server(args)
