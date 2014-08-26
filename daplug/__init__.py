"""
Daplug API

Requires : https://github.com/vpelletier/python-libusb1.git
version 1.1.0
"""

import hid
import random
import time

from conv import *
from utils import *
from sam import *
from exception import DaplugException
from usb import USBDongle, listUSB
from hid import HIDDongle, listHID
from keyset import KeySet

# class TransientKeySet(KeySet):
#     """@TransientKeySet"""

#     def setBlobKey(self, blobKey):
#         """@TransientKeySet.setBlobKey"""
#         pass

class DaplugDongle:
    """@DaplugDongle"""

    def __init__(self, device, name=""):
        """@DaplugDongle.DaplugDongle"""
        self.device = device
        self.name = name
        self.sam = None

        # Init Secure Channel values
        self.sessionOpen = False
        self.securityLevel = None
        self.sencKey = None
        self.cmacKey = None
        self.rmacKey = None
        self.sdekKey = None
        self.rencKey = None
        self.cmac = "0000000000000000"
        self.rmac = "0000000000000000"

    def __exchangeRawApdu(self, apdu, status=0x9000, throwErr=True):
        """Send an APDU to the dongle and get a response"""
        return self.device.exchange(apdu, status, throwErr, self.name)

    def testApdu(self, apdu):
        self.__exchangeRawApdu(apdu)

    def __wrap(self, apdu):
        """
        Wrap an APDU over the Secure Channel

        @param apdu: The APDU to wrap
        """
        securityLevel = self.securityLevel
        if not self.sessionOpen:
            securityLevel = DaplugDongle.C_MAC # c-mac only forced
        workApdu = hex2lst(apdu)
        workApdu[0] = ((workApdu[0] & 0xfc) | 0x04)
        workApdu[4] = workApdu[4] + 8
        workApdu = lst2hex(workApdu)
        if self.sessionOpen:
            workApduForMac = self.cmac + workApdu
        else:
            workApduForMac = workApdu
        if (securityLevel & DaplugDongle.C_MAC) != 0:
            if self.sam is None:
                self.cmac = retailMac(self.cmacKey, workApduForMac)
            else:
                self.cmac = self.sam.computeRetailMac(
                    DaplugSAM.SIGN_CMAC, self.samCtxKeyVer, self.samCtxKeyID,
                    self.cmacKey, workApduForMac)
        if (securityLevel & DaplugDongle.C_DEC) != 0:
            apduData = ""
            if self.sam is None:
                apduData = encryptEnc(self.sencKey, apdu[10:])
            else:
                apduData = self.sam.encryptEnc(
                    self.samCtxKeyVer, self.samCtxKeyID,
                    self.sencKey, apdu[10:])
            updatedDataLength = len(apduData) / 2
            if (securityLevel & DaplugDongle.C_MAC) != 0:
                updatedDataLength = updatedDataLength + 8
            workApdu = workApdu[0:8] + '%02x' % updatedDataLength + apduData
        if (securityLevel & DaplugDongle.C_MAC) != 0:
            workApdu = workApdu + self.cmac
        if not self.sessionOpen:
            self.rmac = self.cmac
        self.sessionOpen = True
        return workApdu

    def __unwrap(self, apdu, answer, sw=0x9000, status=0x9000):
        """
        Unwraps an ANSWER over the Secure Channel

        @param answer: The ANSWER to unwrap
        """
        data = lst2hex(answer)
        securityLevel = self.securityLevel
        if (securityLevel & DaplugDongle.R_MAC) != 0:
            data = lst2hex(answer[:-8])
        if (securityLevel & DaplugDongle.R_ENC) != 0:
            if self.sam is None:
                data = decryptData(self.rencKey, data)
            else:
                data = self.sam.decryptREnc(
                    self.samCtxKeyVer, self.samCtxKeyID,
                    self.rencKey, data)
        if (securityLevel & DaplugDongle.R_MAC) != 0:
            dataLength = len(data) / 2
            cardRmac = lst2hex(answer[-8:])
            workAnswerForMac = apdu + "%02x" % dataLength + data + "%04x" % sw
            calcRmac = ""
            if self.sam is None:
                calcRmac = retailMac(self.rmacKey, workAnswerForMac, self.rmac)
            else:
                calcRmac = self.sam.computeRetailMac(
                    DaplugSAM.SIGN_RMAC, self.samCtxKeyVer, self.samCtxKeyID,
                    self.rmacKey, workAnswerForMac, self.rmac)
            if (cardRmac != calcRmac):
                msg = "Invalid card RMAC " + cardRmac + " vs " + calcRmac
                raise DaplugException(0x8011, msg)
            self.rmac = cardRmac
        if sw != status:
            raise DaplugException(sw, "Invalid Status Word")
        return hex2lst(data)

    def __exchangeApdu(self, apdu, status=0x9000):
        finalApdu = apdu
        if (self.sessionOpen):
            finalApdu = self.__wrap(apdu)
        res = self.__exchangeRawApdu(finalApdu, status, throwErr=False)
        ans = res[0]
        if (self.sessionOpen):
            ans = self.__unwrap(apdu, res[0], res[1], status)
        elif res[1] != status:
            raise DaplugException(res[1], "Invalid Status Word")
            
        return ans

    def __exchangeApdu2(self, header, msg, status=0x9000):
        msgLength = len(msg) / 2
        fullApdu = header + "%02x" % msgLength + msg
        return self.__exchangeApdu(fullApdu)

    def _DaplugSAM__exchangeApdu2(self, header, msg, status=0x9000):
        return self.__exchangeApdu2(header, msg, status)

    def getSerial(self):
        """@DaplugDongle.getSerial"""
        return self.__exchangeApdu("80E6000000")

    def getStatus(self):
        """@DaplugDongle.getStatus"""
        return self.__exchangeApdu("80F2400000")[-2]

    def setStatus(self, status):
        """@DaplugDongle.setStatus"""
        self.__exchangeApdu("80F040%02x00" % status)

    # GP constants
    C_MAC = 0x01
    """@DaplugDongle.C_MAC"""

    C_DEC = 0x02
    """@DaplugDongle.C_DEC"""

    R_MAC = 0x10
    """@DaplugDongle.R_MAC"""

    R_ENC = 0x20
    """@DaplugDongle.R_ENC"""

    def authenticate(self, keys, mode, challenge=None, div=None):
        """@DaplugDongle.authenticate"""
        if (keys.encKey is None or keys.macKey is None or keys.dekKey is None):
            raise DaplugException(0x8001, "Missing key")
        hostChallenge = ""
        # Prepare INITIALIZE UPDATE / EXTERNAL AUTHENTICATE
        if (challenge is None):
            for x in range(8):
                hostChallenge += '%02x' % int(random.uniform(0, 0xff))
        else:
            hostChallenge = challenge
        res = self.__exchangeRawApdu("8050" + '%02x' % keys.version + "0008" + hostChallenge)[0]
        sequenceCounter = lst2hex(res[12:14])
        cardChallenge = lst2hex(res[12:20]) # Get seq + challenge because they are used together
        cardCryptogram = lst2hex(res[20:28])
        self.sencKey = derive(keys.encKey, "0182", sequenceCounter)
        computedCardCryptogram = signSEnc(self.sencKey, hostChallenge + cardChallenge)
        if computedCardCryptogram != cardCryptogram:
            raise DaplugException(0x8010, "Invalid card cryptogram")
        hostCryptogram = signSEnc(self.sencKey, cardChallenge + hostChallenge)

        self.cmacKey = derive(keys.macKey, "0101", sequenceCounter)
        self.rmacKey = derive(keys.encKey, "0102", sequenceCounter)
        self.sdekKey = derive(keys.dekKey, "0181", sequenceCounter)
        self.rencKey = derive(keys.encKey, "0183", sequenceCounter)
        self.securityLevel = mode
        self.cmac = "0000000000000000"
        self.rmac = "0000000000000000"
        extAuthApdu = "8082" + '%02x' % mode + "0008" + hostCryptogram
        externalAuthenticate = self.__wrap(extAuthApdu)
        self.__exchangeRawApdu(externalAuthenticate)[0]

    def authenticateSam(self, sam, samCtxKeyVer, samCtxKeyID, samGPKeyVersion, cardKeyVersion, mode, div1=None, div2=None):
        self.sam = sam
        self.samCtxKeyVer = samCtxKeyVer
        self.samCtxKeyID = samCtxKeyID
        hostChallenge = ""
        for x in range(8):
            hostChallenge += '%02x' % int(random.uniform(0, 0xff))
        print("INITIALIZE_UPDATE")
        res = self.__exchangeRawApdu("8050" + '%02x' % cardKeyVersion + "0008" + hostChallenge)[0]
        sequenceCounter = res[12] * 256 + res[13]
        cardChallenge = lst2hex(res[12:20])
        cardCryptogram = lst2hex(res[20:28])

        # Generate session keys
        flags = DaplugSAM.GENERATE_DEK + DaplugSAM.GENERATE_RMAC + DaplugSAM.GENERATE_RENC
        if div1 is not None: flags += 1
        if div2 is not None: flags += 1
        sessKeys = sam.diversifyGP(samCtxKeyVer, samCtxKeyID, samGPKeyVersion, flags, sequenceCounter, div1, div2)
        for sesskey in sessKeys:
            print("> " + lst2hex(sesskey))

        self.sencKey = lst2hex(sessKeys[0])
        self.cmacKey = lst2hex(sessKeys[1])
        self.sdekKey = lst2hex(sessKeys[2])
        self.rmacKey = lst2hex(sessKeys[3])
        self.rencKey = lst2hex(sessKeys[4])

        computedCardCryptogram = self.sam.sign(
            DaplugSAM.SIGN_ENC, samCtxKeyVer, samCtxKeyID, self.sencKey,
            "00"*8, "00"*9, hostChallenge + cardChallenge
        )
        dalog("Card cryptogram:")
        dalog(computedCardCryptogram + " vs " + cardCryptogram)
        if computedCardCryptogram != cardCryptogram:
            raise DaplugException(0x8010, "Invalid card cryptogram")
        hostCryptogram = self.sam.sign(
            DaplugSAM.SIGN_ENC, samCtxKeyVer, samCtxKeyID, self.sencKey,
            "00"*8, "00"*9, cardChallenge + hostChallenge
        )

        self.securityLevel = mode
        self.cmac = "0000000000000000"
        self.rmac = "0000000000000000"

        extAuthApdu = "8082" + '%02x' % mode + "0008" + hostCryptogram
        print("EXTERNAL_AUTHENTICATE")
        externalAuthenticate = self.__wrap(extAuthApdu)
        self.__exchangeRawApdu(externalAuthenticate)[0]

    def deAuthenticate(self):
        """@DaplugDongle.deAuthenticate"""
        self.sam = None
        self.sessionOpen = False
        self.securityLevel = None
        self.sencKey = None
        self.cmacKey = None
        self.rmacKey = None
        self.sdekKey = None
        self.rencKey = None
        self.cmac = "0000000000000000"
        self.rmac = "0000000000000000"

    def putKey(self, keys):
        """@DaplugDongle.putKey"""
        if self.sam is not None:
            raise DaplugException(0x8000, "Invalid auth method")
        if (keys.encKey is None or keys.macKey is None or keys.dekKey is None):
            raise DaplugException(0x8001, "Missing key")
        if (keys.usage is None):
            raise DaplugException(0x8002, "Missing key usage")
        if (keys.access is None):
            raise DaplugException(0x8003, "Missing key access")

        data = '%02x' % keys.version

        def aux(key):
            acc = "ff8010" + encryptData(self.sdekKey, key)
            acc = acc + "03" + computeKCV(key)
            acc = acc + "01" + '%02x' % keys.usage + "02" + '%04x' % keys.access
            return acc

        data = data + aux(keys.encKey)
        data = data + aux(keys.macKey)
        data = data + aux(keys.dekKey)

        apdu = "80d8" + '%02x' % keys.version + "81"
        apdu = apdu + '%02x' % (len(data) / 2) + data
        self.__exchangeApdu(apdu)

    def putKeySam(self, keyVer, access, usage, samProvKey, div1=None, div2=None, selfParent=False):
        if self.sam is None:
            raise DaplugException(0x8000, "Invalid auth method")
        if selfParent:
            usage = usage + 0x80
        header = "80d8" + '%02x' % keyVer + "81"

        data = '%02x' % keyVer
        keys = self.sam.diversifyPutKey(self.samCtxKeyVer, self.samCtxKeyID, samProvKey, self.sdekKey, div1, div2)

        def aux(i):
            acc = "ff8010" + lst2hex(keys[i][0]) + "03" + lst2hex(keys[i][1])
            acc += "01" + '%02x' % usage
            acc += "02" + '%04x' % access
            return acc

        data += aux(0) + aux(1) + aux(2)

        self.__exchangeApdu2(header, data)

    def exportKey(self, version, keyID):
        """@DaplugDongle.exportKey"""
        pass

    def importKey(self, version, keyID, keys):
        """@DaplugDongle.importKey"""
        pass

    # File constants

    MASTER_FILE = 0x3f00

    ACCESS_ALWAYS = 0x00

    ACCESS_NEVER = 0xFF

    def createFile(self, fileID, size, access=ACCESS_ALWAYS, tag=None):
        """@DaplugDongle.createFile"""
        header = "80E00000"
        msgHead = "62"
        msgCont = "820201218302" + "%04x" % fileID + "8102" + "%04x" % size + "8C0600"
        msgCont += "%02x" % access + "0000" + "%02x" % access + "%02x" % access
        if tag is not None:
            msgCont += tag
        contLength = len(msgCont)
        msg = msgHead + "%02x" % contLength + msgCont
        self.__exchangeApdu2(header, msg)

    def createCounterFile(self, fileID):
        self.selectPath([DaplugDongle.MASTER_FILE, 0xC010])
        self.createFile(fileID, 8, DaplugDongle.ACCESS_ALWAYS, tag="870101")
        # Start the counter at 1
        self.write(0, "0000000000000001")

    def createDir(self, fileID, access):
        """@DaplugDongle.createDir"""
        header = "80E00000"
        msg = "620E820232218302" + "%04x" % fileID + "8C0400"
        msg = msg + "%02x" % access + "%02x" % access + "%02x" % access
        self.__exchangeApdu2(header, msg)

    def deleteFileOrDir(self, fileID):
        """@DaplugDongle.deleteFileOrDir"""
        apdu = "80E4000002" + "%04x" % fileID
        self.__exchangeApdu(apdu)

    def selectFile(self, fileID):
        """@DaplugDongle.selectFile"""
        apdu = "80A4000002" + "%04x" % fileID
        self.__exchangeApdu(apdu)

    def selectPath(self, fileIDs):
        """@DaplugDongle.selectPath"""
        for fileID in fileIDs:
            self.selectFile(fileID)

    def deleteKeys(self, keyVersions):
        """@DaplugDongle.deleteKeys"""
        self.selectPath([DaplugDongle.MASTER_FILE, 0xc00f, 0xc0de, 0x0001])
        for key in keyVersions:
            self.deleteFileOrDir(0x1000 + key)
        self.selectFile(DaplugDongle.MASTER_FILE)

    def deleteKey(self, keyVersion):
        """@DaplugDongle.deleteKey"""
        self.deleteKeys([keyVersion])

    def read(self, offset, length):
        """@DaplugDongle.read"""
        partLen = 0xEF
        res = []
        def aux(subOffset, subLen):
            apdu = "80B0" + "%04x" % subOffset
            if self.sessionOpen:
                apdu = apdu + "00"
            else:
                apdu = apdu + "%02x" % length
            return self.__exchangeApdu(apdu)[:2*subLen]
        dataLen = length
        dataOffset = 0
        while dataLen > partLen:
            res += aux(offset + dataOffset, partLen)
            dataLen -= partLen
            dataOffset += partLen
        if dataLen > 0:
            res += aux(offset + dataOffset, dataLen)
        return res

    def write(self, offset, data):
        """@DaplugDongle.write"""
        partLen = 0xEF
        def aux(subOffset, subData, subDataLen):
            apdu = "80D6" + "%04x" % subOffset + "%02x" % subDataLen + subData
            self.__exchangeApdu(apdu)
        dataLen = len(data) / 2
        dataOffset = 0
        while dataLen > partLen:
            aux(dataOffset+offset, data[2*dataOffset:2*(dataOffset+partLen)], partLen)
            dataOffset += partLen
            dataLen -= partLen
        if dataLen > 0:
            aux(dataOffset+offset, data[2*dataOffset:], dataLen)

    # Encrypt/Decrypt Constants
    CRYPT_ECB  = 0x01
    CRYPT_CBC  = 0x02
    CRYPT_DIV1 = 0x04
    CRYPT_DIV2 = 0x08

    def __cryptDecrypt(self, keyVersion, keyID, act, mode, data, iv, div1, div2):
        if (len(data) % 16 != 0):
            raise DaplugException(0x8010, "Data length must be a multiple of 8 bytes")
        header = "D020" + "%02x" % act + "%02x" % mode
        cont = "%02x" % keyVersion + "%02x" % keyID
        cont += iv
        if (div1 is not None):
            cont += div1
        if (div2 is not None):
            cont += div2
        cont = cont + data
        print(header)
        print(cont)
        return self.__exchangeApdu2(header, cont)

    def encrypt(self, keyVersion, keyID, mode, data, iv="0000000000000000", div1=None, div2=None):
        """@DaplugDongle.encrypt"""
        return self.__cryptDecrypt(keyVersion, keyID, 0x01, mode, data, iv, div1, div2)

    def decrypt(self, keyVersion, keyID, mode, data, iv="0000000000000000", div1=None, div2=None):
        """@DaplugDongle.decrypt"""
        return self.__cryptDecrypt(keyVersion, keyID, 0x02, mode, data, iv, div1, div2)

    def getRandom(self, length):
        """@DaplugDongle.getRandom"""
        apdu = "D0240000"+ "%02x" % length + ("0" * 2*length)
        return self.__exchangeApdu(apdu)

    # OATH HOTP/TOTP

    # xOTP Constants
    OTP_0_DIV     = 0x00
    """@DaplugDongle.OTP_0_DIV"""

    OTP_1_DIV     = 0x01
    """@DaplugDongle.OTP_1_DIV"""

    OTP_2_DIV     = 0x02
    """@DaplugDongle.OTP_2_DIV"""

    OTP_6_DIGIT  = 0x10
    """@DaplugDongle.HOTP_6_DIGIT"""

    OTP_7_DIGIT  = 0x20
    """@DaplugDongle.HOTP_7_DIGIT"""

    OTP_8_DIGIT = 0x40
    """@DaplugDongle.HOTP_8_DIGIT"""

    HOTP_DATA_FILE = 0x80
    """@DaplugDongle.HOTP_DATA_FILE"""

    def hmac(self, keyVersion, options, data, div1=None, div2=None):
        """@DaplugDongle.hmac"""
        header = "D022" + "%02x" % keyVersion + "%02x" % options
        cont = ""
        if (div1 is not None):
            cont += + div1
        if (div2 is not None):
            cont += + div2
        cont += data
        return self.__exchangeApdu2(header, cont)

    def hotp(self, keyVersion, options, data, div1=None, div2=None):
        """@DaplugDongle.hotp"""
        pass

    def setTotpTimeKey(self, keyVersion, hexKey):
        """@DaplugDongle.setTotpTimeKey"""
        timeKey = KeySet(keyVersion, hexKey) 
        timeKey.setKeyAccess(0x0001)
        timeKey.setKeyUsage(KeySet.USAGE_TOTP_TIME_SRC)
        self.putKey(timeKey)

    def setTotpKeyHexa(self, keyVersion, timeKeyVersion, hexKey):
        """@DaplugDongle.setTotpKeyHexa"""
        keyLen = len(hexKey) / 2
        keys = splitKey(hexKey)
        totpKey = KeySet(keyVersion, keys[0], keys[1], keys[2])
        totpKey.setKeyAccess((timeKeyVersion << 8) + keyLen)
        totpKey.setKeyUsage(KeySet.USAGE_TOTP)
        self.putKey(totpKey)

    def setTotpKeyBase32(self, keyVersion, timeKeyVersion, base32Key):
        """@DaplugDongle.setTotpKeyBase32"""
        hexKey = base32toHex(base32Key)
        self.setTotpKeyHexa(keyVersion, timeKeyVersion, hexKey)

    def totp(self, keyVersion, options, div1=None, div2=None):
        """@DaplugDongle.totp"""
        ans = self.hmac(keyVersion, options, "", div1, div2)
        totp = ""
        for code in ans:
            totp = totp + chr(code)
        return totp

    def setTimeOTP(self, keyVersion, keyID, key, curTime=None, step=30):
        """@DaplugDongle.setTimeOTP"""
        import time
        if curTime is None:
            curTime = int(time.time())
        timeRef = ""
        for x in range(11):
            timeRef = timeRef + '%02x' % int(random.uniform(0, 0xff))
        timeRef = timeRef + "1E" + "%08x" % curTime
        sig = cbcDES(key, timeRef)
        fullTimeRef = timeRef + sig[16:]
        header = "D0B2" + "%02x" % keyVersion + "%02x" % keyID
        self.__exchangeApdu2(header, fullTimeRef)

    def getTimeOTP(self):
        """@DaplugDongle.getTimeOTP"""
        pass

    def useAsKeyboard(self):
        """@DaplugDongle.useAsKeyboard"""
        self.__exchangeApdu("D032000000")

    def setKeyboardAtBoot(self, activated):
        """@DaplugDongle.setKeyboardAtBoot"""
        apdu = "D032"
        if activated:
            apdu = apdu + "020000"
        else:
            apdu = apdu + "010000"
        self.__exchangeApdu(apdu)

    def triggerKeyboard(self):
        """@DaplugDongle.triggerKeyboard"""
        self.__exchangeApdu("D030010000")

    def getMode(self):
        """@DaplugDongle.getMode"""
        return self.device.getMode()

    def hid2usb(self):
        """@DaplugDongle.hid2usb"""
        if self.device.getMode() == "hid":
            self.__exchangeApdu("D052080200")
        else:
            raise DaplugException(0x8901, "Not in HID mode")

    def usb2hid(self):
        """@DaplugDongle.usb2hid"""
        if self.device.getMode() == "usb":
            self.__exchangeApdu("D052080100")
        else:
            raise DaplugException(0x8902, "Not in USB mode")

    def reset(self):
        """@DaplugDongle.reset"""
        self.__exchangeApdu("D052010000")

    def halt(self):
        """@DaplugDongle.halt"""
        self.__exchangeApdu("D052020000")

    def getChipDiversifier(self):
        serial = self.getSerial()
        # first 10 bytes of serial
        res = serial[0:10]
        # first 6 bytes XOR 0x42
        for n in serial[0:6]:
            res.append(n ^ 0x42)
        return lst2hex(res)

# Static methods

def getDongleList():
    """@DaplugDongle.getDongleList"""
    devices = []
    for device in listHID():
        devices.append(("hid", device))
    for device in listUSB():
        devices.append(("usb", device))
    return devices

def getDongle((mode, dongle), name=""):
    """@DaplugDongle.getDongle"""
    if mode == "hid":
        device = HIDDongle(dongle)
    else:
        device = USBDongle(dongle)
    return DaplugDongle(device, name)

def getFirstDongle(name=""):
    """Convenience function to return the first available dongle"""
    return getDongle(getDongleList()[0], name)

def getPort(device):
    portNum = device.getPortNumberList()
    portNum[:0] = [device.getBusNumber()]
    return portNum

def getDongleByPort(port, name=""):
    res = None
    for (mode,dongle) in getDongleList():
        if getPort(dongle) == port:
            res = getDongle((mode, dongle), name)
    return res
