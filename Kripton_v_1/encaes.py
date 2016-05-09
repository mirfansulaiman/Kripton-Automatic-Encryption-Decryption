#!/usr/bin/env python
# Replace with your the best encryption
# 
# This encryption use AES 256 code from here :
# http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
import base64
import time
from Crypto import Random
from Crypto.Cipher import AES
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]
class AESCipher:
    def __init__( self, key ):
        self.key = key
    def encrypt( self, raw ): #Dont Remove
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )
    def decrypt( self, enc ):  #Dont Remove
        enc = enc.rstrip()
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))
