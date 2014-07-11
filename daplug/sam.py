"""
Daplug SAM API
"""

from conv import *
from utils import *
from exception import DaplugException

class DaplugSAM:

    BLOCK = 0xD8

    # SAM constants for diversifyGP
    DIV1          = 0x01
    DIV2          = 0x02
    GENERATE_DEK  = 0x04
    GENERATE_RMAC = 0x08
    GENERATE_RENC = 0x10

    # act for sign
    SIGN_ENC  = 0x10
    SIGN_CMAC = 0x20
    SIGN_RMAC = 0x30

    def __init__(self, dongle):
        self.d = dongle

    def diversifyGP(self, keyVer, keyID, gpKeyVersion, flags, seq, div1=None, div2=None):
        print("DIV GP: %02x %02x %02x %02x %04x" % (keyVer, keyID, gpKeyVersion, flags, seq))
        header = "D0700010"
        cont = "%02x%02x%02x%02x" % (keyVer, keyID, gpKeyVersion, flags)
        cont += "%04x" % seq
        if (div1 is not None): cont += div1
        if (div2 is not None): cont += div2
        keys = self.d.__exchangeApdu2(header, cont)
        return [keys[i:i+24] for i in range(0, len(keys), 24)]

    def diversifyPutKey(self, keyVer, keyID, samProvKeyVersion, dekSession, div1=None, div2=None):
        header = "D0700020"
        flags = 0
        if (div1 is not None): flags += 1
        if (div2 is not None): flags += 1
        cont = "%02x%02x%02x%02x" % (keyVer, keyID, samProvKeyVersion, flags)
        cont += dekSession
        if (div1 is not None): cont += div1
        if (div2 is not None): cont += div2
        keys = self.d.__exchangeApdu2(header, cont)
        return [(keys[i:i+16], keys[i+16:i+19]) for i in range(0, len(keys), 19)]

    def diversifyCleartext(self, keyVer, div1=None, div2=None):
        header = "D0700030"
        flags = 0
        if (div1 is not None): flags += 1
        if (div2 is not None): flags += 1
        cont = "0000%02x%02x" % (keyVer, flags)
        if (div1 is not None): cont += div1
        if (div2 is not None): cont += div2
        keys = self.d.__exchangeApdu2(header, cont)
        return [keys[i:i+16] for i in range(0, len(keys), 16)]

    def __cryptDecrypt(self, act, keyVer, keyID, sess, iv, cipherCtx, content, lastBlock):
        header = "D072"
        if lastBlock: header += "80"
        else: header += "00"
        header += "%02x" % act
        cont = "%02x%02x" % (keyVer, keyID)
        cont += sess + iv + cipherCtx + content
        return lst2hex(self.d.__exchangeApdu2(header, cont))

    def __encryptEnc(self, keyVer, keyID, cEncSess, iv, cipherCtx, content, lastBlock=True):
        if len(content) % 16 != 0:
            raise DaplugException(0x8101, "Content length must be a multiple of 8 bytes")
        return self.__cryptDecrypt(0x10, keyVer, keyID, cEncSess, iv, cipherCtx, content, lastBlock)

    def __encryptDek(self, keyVer, keyID, dekSess, content, lastBlock=True):
        return self.__cryptDecrypt(0x20, keyVer, keyID, dekSess, "00"*8, "00"*9, content, lastBlock)

    def __decryptREnc(self, keyVer, keyID, rEncSess, iv, cipherCtx, content, lastBlock=True):
        return self.__cryptDecrypt(0x30, keyVer, keyID, rEncSess, iv, cipherCtx, content, lastBlock)

    def sign(self, act, keyVer, keyID, sess, iv, signCtx, content, lastBlock=True):
        header = "D074"
        if lastBlock: header += "80"
        else: header += "00"
        header += "%02x" % act
        cont = "%02x%02x" % (keyVer, keyID)
        cont += sess + iv + signCtx + content
        # dalog("SIGN: " + cont)
        return lst2hex(self.d.__exchangeApdu2(header, cont))

    def __multiprocess(self, act, data, iv=None):
        BLOCK = self.BLOCK
        context = "00"*9
        if iv is None:
            iv = "00"*8
        nbParts = 1 + len(data)/2/BLOCK
        accRes = ""
        for i in range(nbParts):
            last = i == (nbParts - 1)
            cont = data[i*BLOCK*2:(i+1)*BLOCK*2]
            res = act(iv, context, cont, last)
            if not last:
                iv = res[0:16]
                context = res[16:34]
                accRes += res[34:]
            else:
                accRes += res
        return accRes

    def computeRetailMac(self, act, keyVer, keyID, sess, data, iv=None):
        def f(iv, context, cont, last):
            return self.sign(act, keyVer, keyID, sess, iv, context, cont, last)
        return self.__multiprocess(f, data, iv)

    def encryptEnc(self, keyVer, keyID, sess, data):
        def f(iv, context, cont, last):
            return self.__encryptEnc(keyVer, keyID, sess, iv, context, cont, last)
        return self.__multiprocess(f, data)
        
    def decryptREnc(self, keyVer, keyID, sess, data):
        def f(iv, context, cont, last):
            return self.__decryptREnc(keyVer, keyID, sess, iv, context, cont, last)
        return self.__multiprocess(f, data)
