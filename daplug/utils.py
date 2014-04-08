"""
Daplug utility functions

Contains mostly cryptographic functions
"""

from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from conv import *

DEBUG = True

ZERO = hex2txt("0"*16)

def dalog(src):
    if (DEBUG):
        print(src)

def zeroPad(data):
    """Add binary zeroes to a string to have a size multiple of 64"""
    "data in 'txt' format"
    l = len(data) % 64
    padding = "\x00" * 64
    return data + padding[0:64-l]

def derive(key, deriveData, sequenceCounter):
    """Derive session keys for the given diversifier and sequence counter"""
    data = deriveData + sequenceCounter + "000000000000000000000000"
    des = DES3.new(key, DES3.MODE_CBC, ZERO)
    return des.encrypt(hex2txt(data))

def signSEnc(sencKey, data):
    """Sign data using the ENC session key"""
    dataToSign = data + "8000000000000000"
    des = DES3.new(sencKey, DES3.MODE_CBC, ZERO)
    res = des.encrypt(hex2txt(dataToSign))
    return txt2hex(res[16:])

def retailMac(cmacKey, data, iv="0000000000000000"):
    """Compute the Retail MAC for an APDU"""
    paddingSize = 8 - ((len(data) / 2) % 8)
    workData = data + "8000000000000000"[0:paddingSize * 2]
    des = DES.new(cmacKey[0:8], DES.MODE_CBC, hex2txt(iv))
    res = des.encrypt(hex2txt(workData))
    lastBlock = res[len(res) - 8:]
    des = DES.new(cmacKey[8:16], DES.MODE_ECB)
    lastBlock = des.decrypt(lastBlock)
    des = DES.new(cmacKey[0:8], DES.MODE_ECB)
    return txt2hex(des.encrypt(lastBlock))

def encryptEnc(sencKey, data):
    """Encrypt APDU command using the ENC session key"""
    paddingSize = 8 - ((len(data) / 2) % 8)
    workData = data + "8000000000000000"[0:paddingSize * 2]
    des = DES3.new(sencKey, DES.MODE_CBC, ZERO)
    return txt2hex(des.encrypt(hex2txt(workData)))

def encryptData(sdekKey, data):
    """Encrypt APDU data using the DEK session key"""
    des = DES3.new(sdekKey, DES3.MODE_ECB)
    res = des.encrypt(data)
    return txt2hex(res)

def cbcDES(key, data):
    """Encrypt data with CBC DES"""
    des = DES3.new(hex2txt(key), DES.MODE_CBC)
    res = des.encrypt(hex2txt(data))
    return txt2hex(res)

def computeKCV(data):
    """Compute a KCV for the PUT KEY command"""
    des = DES3.new(data, DES3.MODE_CBC)
    res = des.encrypt(ZERO)
    return txt2hex(res[0:3])

def hexUnpad(data):
    def aux(i):
        sub = data[i:i+2]
        if sub == "00":
            return aux(i-2)
        elif sub == "80":
            return data[:i]
        else:
            return data
    return aux(len(data) - 2)

def decryptData(rencKey, data, iv="0000000000000000"):
    """Decrypt APDU data using the ENC session key"""
    if data == "":
        return ""
    else:
        des = DES3.new(rencKey, DES3.MODE_CBC, hex2txt(iv))
        res = des.decrypt(hex2txt(data))
        return hexUnpad(txt2hex(res))

BASE2 = "01"
BASE10 = "0123456789"
BASE16 = "0123456789ABCDEF"
BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BASE62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"

def normalizeBase32(data):
    res = ""
    for char in data:
        normChar = char.upper()
        if (normChar == '0'):
            normChar = "O"
        if (normChar == '1'):
            normChar = "L"
        if (normChar == '8'):
            normChar = "B"
        if normChar in BASE32:
            res = res + normChar
    return res

def baseConvert(number,fromdigits,todigits):
    """ Converts a "number" between two bases of arbitrary digits """
    if fromdigits == BASE32:
        number = normalizeBase32(number)

    if str(number)[0]=='-':
        number = str(number)[1:]
        neg = 1
    else:
        neg = 0

    # make an integer out of the number
    x = long(0)
    for digit in str(number):
       x = x * len(fromdigits) + fromdigits.index(digit)
    
    # create the result in base 'len(todigits)'
    res = ""
    while x > 0:
        digit = x % len(todigits)
        res = todigits[digit] + res
        x /= len(todigits)
    if neg:
        res = "-" + res

    return res

def base32toHex(data):
    """ Converts a "number" from BASE32 to BASE16 """
    return baseConvert(data, BASE32, BASE16)

def splitKey(key):
    """ Split a key in 3 subkeys """
    paddedKey = key
    while len(paddedKey) < 96:
        paddedKey = paddedKey + "00"
    return (paddedKey[0:32], paddedKey[32:64], paddedKey[64:96])
