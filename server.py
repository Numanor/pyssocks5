# -*- coding: utf-8 -*-
import sys 
import struct
import signal
import argparse

import gevent
from gevent import socket
from gevent.server import StreamServer
from gevent.socket import create_connection, gethostbyname

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_v1_5 as RSACipher
from Crypto.Signature import PKCS1_v1_5 as RSASignature
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA
from utils.SSocket import SSocket
from utils.socks import *

class SocksServer(StreamServer):
    def __init__(self, listen, args):
        super(SocksServer, self).__init__(listen)
        # remote pub key: encrypt outflow data & verify signature
        with open(args.remote_pub) as f:
            remote_pubkey = RSA.importKey(f.read())
        self.remote_cipher = RSACipher.new(remote_pubkey)
        self.remote_verifier = RSASignature.new(remote_pubkey)
        # local private key: decrypt inflow data & sign
        with open(args.private) as f:
            privatekey = RSA.importKey(f.read())
        self.local_cipher = RSACipher.new(privatekey)
        self.local_signer = RSASignature.new(privatekey)

    def handle(self, sock, addr):
        print('connection from %s:%s' % addr)
        src = SSocket(socket=sock)

        """
            Establish Secure Connection with remote server
        """
        # 1. Exchange Session Key
        # 1.1 decrypt the received session key
        ciphertext = src.recv(256)
        session_key = self.local_cipher.decrypt(ciphertext, sentinel=Random.new().read(16+16))
        aes_key = session_key[:16]
        aes_iv = session_key[16:]
        # 1.2 set up AES encrypted transmission
        src.aes_init(aes_key, AES.MODE_CBC, aes_iv)

        # 2. RSA Authentication - remote
        # 2.1 decrypt the received signature
        signature = src.aes_recv()
        # 2.2 verify
        h = SHA.new(session_key)
        if not self.remote_verifier.verify(h, signature):
            return
        
        # 3. RSA Authentication - local
        # 3.1 sign session key with local private key
        h = SHA.new(session_key)
        signature = self.local_signer.sign(h)
        # 3.2 send the signature, encrypted by session key
        src.aes_send(signature)

        """
            socks5 negotiation step2: specify command and destination
        """
        ver, cmd, rsv, atype = src.aes_unpack('BBBB', 4)
        
        # 1. only support 'connect' command
        if cmd != SOCKS_CMD_CONNECT:
            src.aes_pack('BBBBIH', SOCKS_VERSION_V, SOCKS_REP_CMD_UNK, 0x00, 0x01, 0, 0)
            return

        # 2. only support ipv4/domain name address type
        if atype == SOCKS_ATYP_IPV4: #ipv4
            host, port = src.aes_unpack('!IH', 6)
            hostip = socket.inet_ntoa(struct.pack('!I', host))
        elif atype == SOCKS_ATYP_DOMAIN: #domain name
            length = src.aes_unpack('B', 1)[0]
            hostname, port = src.aes_unpack("!%dsH" % length, length + 2)
            hostip = gethostbyname(hostname)
            host = struct.unpack("!I", socket.inet_aton(hostip))[0]
        else:
            src.aes_pack('!BBBBIH', SOCKS_VERSION_V, SOCKS_REP_CMD_UNK, 0x00, 0x01, 0, 0)
            return
        
        """
            Connect to destination & start forwarding
        """
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
    def start_server(args):
        server = SocksServer(('0.0.0.0', args.port), args)
        gevent.signal(signal.SIGTERM, server.close)
        gevent.signal(signal.SIGINT, server.close)
        print("Server is listening on 0.0.0.0:%d" % args.port)
        server.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', default=9099, type=int)
    parser.add_argument('--remote_pub', default="keys/local.pub")
    parser.add_argument('--private', default="keys/remote")
    args = parser.parse_args()
    SocksServer.start_server(args)