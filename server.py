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
from SSocket import SSocket
from utils.socks import *

class SocksServer(StreamServer):
    def handle(self, sock, addr):
        print('connection from %s:%s' % addr)
        src = SSocket(socket=sock)

        # aes set up
        aes_key = src.recv(16)
        aes_iv = src.recv(16)
        src.aes_init(aes_key, AES.MODE_CBC, aes_iv)
        # recv remote host
        host, port = src.aes_unpack('!IH', 6)
        hostip = socket.inet_ntoa(struct.pack('!I', host))
        print "recv host %s:%d" % (hostip, port)
        # set up remote connection
        try:
            dest = SSocket(addr = (hostip, port))
        except IOError as ex:
            print("%s:%d" % addr, "failed to connect to %s:%d" % (hostip, port))
            src.aes_pack('!BBBBIH', SOCKS_VERSION_V, SOCKS_REP_NET_ERO, 0x00, 0x01, host, port)
            return
        src.aes_pack('!BBBBIH', SOCKS_VERSION_V, SOCKS_REP_CON_SUC, 0x00, SOCKS_ATYP_IPV4, host, port)
        
        gevent.spawn(src.aes_dec_forward, dest)
        gevent.spawn(dest.aes_enc_forward, src)

    def close(self):
        sys.exit(0)

    @staticmethod
    def start_server(port):
        server = SocksServer(('0.0.0.0', port))
        gevent.signal(signal.SIGTERM, server.close)
        gevent.signal(signal.SIGINT, server.close)
        print("Server is listening on 0.0.0.0:%d" % port)
        server.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', default=9099, type=int)
    args = parser.parse_args()
    SocksServer.start_server(args.port)