# -*- coding: utf-8 -*-
import gevent
import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto.Random import get_random_bytes

class SSocket(gevent.socket.socket):
    def __init__(self, socket = None, addr = None):
        if socket is not None:
            gevent.socket.socket.__init__(self, _sock=socket)
        elif addr is not None:
            gevent.socket.socket.__init__(self)
            self.connect(addr)
        else:
            raise Exception("SSocket.init: bad arguments")
        self.aes_recvbuf = ''

    def unpack(self, fmt, length):
        data = self.recv(length)
        if len(data) < length:
            raise Exception("SSocket.unpack: bad formatted stream")
        return struct.unpack(fmt, data)

    def pack(self, fmt, *args):
        data = struct.pack(fmt, *args)
        return self.sendall(data)
    
    def aes_init(self, key, mode, iv):
        self.aes = AES.new(key, mode, iv)
        self.aes_recvbuf = ''
    
    def aes_send(self, data):
        data_len = len(data)
        # 1. pin SHA digest
        digest = SHA.new(data).digest()
        data_d = data + digest
        data_d_len = data_len + SHA.digest_size
        # 2. data padding
        pad_len = data_d_len % AES.block_size
        pad_len = AES.block_size - pad_len if pad_len else 0
        plaintext = data_d + get_random_bytes(pad_len)
        total_len = data_d_len + pad_len
        # 3. encrypt data
        ciphertext = self.aes.encrypt(plaintext)
        # 4.1 send header
        self.pack('HH', total_len, data_len)
        # 4.2 send ciphertext
        self.sendall(ciphertext)

    def aes_recv(self):
        # 1. parse header
        header = self.recv(4)
        if not header:
            return None
        total_len, data_len = struct.unpack('HH', header)
        # 2. read & decrypt ciphertext
        ciphertext = self.recv(total_len)
        plaintext = self.aes.decrypt(ciphertext)
        data_d = plaintext[:data_len + SHA.digest_size]
        # 3. SHA verification
        data = data_d[:data_len]
        recv_digest = data_d[-SHA.digest_size:]
        comp_digest = SHA.new(data).digest()
        if recv_digest != comp_digest:
            raise Exception("SSocket.aes_recv: SHA digest mismatch")
        return data
    
    def aes_pack(self, fmt, *args):
        data = struct.pack(fmt, *args)
        return self.aes_send(data)
    
    def aes_unpack(self, fmt, length):
        data = self.aes_recvbuf
        while len(data) < length:
            recvdata = self.aes_recv()
            if not recvdata:
                raise Exception("SSocket.aes_unpack: bad formatted stream")
            data += recvdata
        self.aes_recvbuf = data[length:]
        data = data[:length]
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