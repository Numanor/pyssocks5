# -*- coding: utf-8 -*-
import gevent
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class SSocket(gevent.socket.socket):
    def __init__(self, socket = None, addr = None):
        if socket is not None:
            gevent.socket.socket.__init__(self, _sock=socket)
        elif addr is not None:
            gevent.socket.socket.__init__(self)
            self.connect(addr)
        else:
            raise Exception("XSocket.init: bad arguments")

    def unpack(self, fmt, length):
        data = self.recv(length)
        if len(data) < length:
            raise Exception("XSocket.unpack: bad formatted stream")
        return struct.unpack(fmt, data)

    def pack(self, fmt, *args):
        data = struct.pack(fmt, *args)
        return self.sendall(data)
    
    def aes_init(self, key, mode, iv):
        self.aes = AES.new(key, mode, iv)
    
    def aes_send(self, data):
        data_len = len(data)
        # 1. data padding
        pad_len = data_len % AES.block_size
        pad_len = AES.block_size - pad_len if pad_len else 0
        data_padded = data + get_random_bytes(pad_len)
        enc_len = data_len + pad_len
        # 2. encrypt data
        enc_data = self.aes.encrypt(data_padded)
        self.pack('HH', enc_len, data_len)
        # 3. send ciphertext
        self.sendall(enc_data)
        # print "data sent"

    def aes_recv(self):
        header = self.recv(4)
        if not header:
            return None
        enc_len, data_len = struct.unpack('HH', header)
        enc_data = self.recv(enc_len)
        dec_data = self.aes.decrypt(enc_data)
        data = dec_data[:data_len]
        return data
    
    def aes_pack(self, fmt, *args):
        data = struct.pack(fmt, *args)
        return self.aes_send(data)
    
    def aes_unpack(self, fmt, length):
        data = self.aes_recv()
        if len(data) < length:
            raise Exception("SSocket.aes_unpack: bad formatted stream")
        return struct.unpack(fmt, data)

    def aes_enc_forward(self, dest):
        try:
            while True:
                data = self.recv(1024)
                if not data:
                    break
                dest.aes_send(data)
        finally:
            self.close()
            dest.close()
    
    def aes_dec_forward(self, dest):
        try:
            while True:
                data = self.aes_recv()
                if not data:
                    break
                dest.sendall(data)
        finally:
            self.close()
            dest.close()