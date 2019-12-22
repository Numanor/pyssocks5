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
from SSocket import SSocket
from utils.socks import *

class SocksLocalServer(StreamServer):
    def __init__(self, listen, args):
        super(SocksLocalServer, self).__init__(listen)
        self.remote_ip = args.remote_ip
        self.remote_port = args.remote_port
        # remote pub key: encrypt outflow data & verify signature
        with open(args.remote_pub) as f:
            remote_pubkey = RSA.importKey(f.read())
            print remote_pubkey.size()
        self.remote_cipher = RSACipher.new(remote_pubkey)
        self.remote_verifier = RSASignature.new(remote_pubkey)
        # local private key: decrypt inflow data & sign
        with open(args.private) as f:
            privatekey = RSA.importKey(f.read())
            print privatekey.size()
        self.local_cipher = RSACipher.new(privatekey)
        self.local_signer = RSASignature.new(privatekey)

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

            p.s. step2(specify command and destination) finished on remote server
        """
        ver, n_method = src.unpack('BB', 2) 
        # 1. socks version
        if ver != SOCKS_VERSION_V:    # SOCKS Protocol Version 5 (RFC 1928)
            src.pack('BB', SOCKS_VERSION_V, SOCKS_NO_ACCEPT_METHOD)
            return
        # 2. authentication method
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
        # 3. auth method negotiation succeed
        src.pack('!BB', SOCKS_VERSION_V, SOCKS_AUTH_NONE)


        """
            Establish Secure Connection with remote server
        """
        # 1. Connect to remote proxy
        try:
            dest = SSocket(addr = (self.remote_ip, self.remote_port))
        except IOError, ex:
            print "%s:%d" % addr, "failed to connect to %s:%d" % ("127.0.0.1", 9099)
            src.pack('!BBBBIH', SOCKS_VERSION_V, SOCKS_REP_NET_ERO, 0x00, 0x01, 0, 0)
            return
        # 2. Exchange Session Key
        # 2.1 gen Session Key(AES key, iv)
        aes_key = get_random_bytes(16)
        aes_iv = get_random_bytes(16)
        # 2.2 encrypt with pubkey of remote server
        session_key = aes_key + aes_iv
        ciphertext = self.remote_cipher.encrypt(session_key)
        # 2.3 send to remote server
        dest.sendall(ciphertext)
        # 2.4 set up AES encrypted transmission
        dest.aes_init(aes_key, AES.MODE_CBC, aes_iv)

        # 3. RSA Authentication - local
        # 3.1 sign session key with local private key
        h = SHA.new(session_key)
        signature = self.local_signer.sign(h)
        # 3.2 send the signature, encrypted by session key
        dest.aes_send(signature)

        # 4. RSA Authentication - remote
        # 4.1 decrypt the received signature
        signature = dest.aes_recv()
        # 4.2 verify
        h = SHA.new(session_key)
        if not self.remote_verifier.verify(h, signature):
            return

        # Finally, start forwarding daemon
        gevent.spawn(src.aes_enc_forward, dest)
        gevent.spawn(dest.aes_dec_forward, src)


    def close(self):
        sys.exit(0)

    @staticmethod
    def start_server(args):
        server = SocksLocalServer(('0.0.0.0', args.port), args)
        gevent.signal(signal.SIGTERM, server.close)
        gevent.signal(signal.SIGINT, server.close)
        print("Server is listening on 0.0.0.0:%d" % args.port)
        server.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', default=9011, type=int)
    parser.add_argument('--remote_ip', default="127.0.0.1")
    parser.add_argument('--remote_port', default=9099, type=int)
    parser.add_argument('--remote_pub', default="keys/remote.pub")
    parser.add_argument('--private', default="keys/local")
    args = parser.parse_args()
    SocksLocalServer.start_server(args)
