"""
Daplug keyset creation class
"""

from conv import *

class KeySet:
    """@KeySet"""

    # Key constants

    USAGE_GP                      = 0x01
    """@KeySet.USAGE_GP"""

    USAGE_GP_AUTH                 = 0x02
    """@KeySet.USAGE_GP_AUTH"""

    USAGE_HOTP                    = 0x03
    """@KeySet.USAGE_HOTP"""

    USAGE_HOTP_VALIDATION         = 0x04
    """@KeySet.USAGE_HOTP_VALIDATION"""

    USAGE_OTP                     = 0x05
    """@KeySet.USAGE_OTP"""

    USAGE_ENC                     = 0x06
    """@KeySet.USAGE_ENC"""

    USAGE_DEC                     = 0x07
    """@KeySet.USAGE_DEC"""

    USAGE_ENC_DEC                 = 0x08
    """@KeySet.USAGE_ENC_DEC"""

    USAGE_SAM_CTX                 = 0x09
    """@KeySet.USAGE_SAM_CTX"""

    USAGE_SAM_GP                  = 0x01
    """@KeySet.USAGE_SAM_GP"""

    USAGE_SAM_DIV1                = 0x0B
    """@KeySet.USAGE_SAM_DIV1"""

    USAGE_SAM_DIV2                = 0x0C
    """@KeySet.USAGE_SAM_DIV2"""

    USAGE_SAM_CLEAR_EXPORT_DIV1   = 0x0D
    """@KeySet.USAGE_SAM_CLEAR_EXPORT_DIV1"""

    USAGE_SAM_CLEAR_EXPORT_DIV2   = 0x0E
    """@KeySet.USAGE_SAM_CLEAR_EXPORT_DIV2"""

    USAGE_IMPORT_EXPORT_TRANSIENT = 0x0F
    """@KeySet.USAGE_IMPORT_EXPORT_TRANSIENT"""

    USAGE_TOTP_TIME_SRC           = 0x10
    """@KeySet.USAGE_TOTP_TIME_SRC"""

    USAGE_TOTP                    = 0x11
    """@KeySet.USAGE_TOTP"""

    USAGE_HMAC_SHA1               = 0x12
    """@KeySet.USAGE_HMAC_SHA1"""


    def __init__(self, version=None, encKey=None, macKey=None, dekKey=None):
        """@KeySet.KeySet"""
        self.usage = None
        self.access = None
        if (version is not None):
            self.version = version

        self.encKey = None
        if encKey is not None:
            self.encKey = hex2txt(encKey)

        self.macKey = None
        if macKey is not None:
            self.macKey = hex2txt(macKey)
        if macKey is None and encKey is not None:
            self.macKey = self.encKey

        self.dekKey = None
        if dekKey is not None:
            self.dekKey = hex2txt(dekKey)
        if dekKey is None and encKey is not None:
            self.dekKey = self.encKey

    def setVersion(self, version):
        """@KeySet.setVersion"""
        self.version = version

    def getVersion(self):
        """@KeySet.getVersion"""
        return self.version

    def setKey(self, id, keyValue):
        """@KeySet.setKey"""
        if (id == 0x01):
            self.encKey = hex2txt(keyValue)
        elif (id == 0x02):
            self.macKey = hex2txt(keyValue)
        elif (id == 0x03):
            self.dekKey = hex2txt(keyValue)
        else:
            raise DaplugException(0x8000, "Invalid key number")

    def getKey(self, id):
        """@KeySet.getKey"""
        if (id == 0x01):
            return txt2hex(self.encKey)
        elif (id == 0x02):
            return txt2hex(self.macKey)
        elif (id == 0x03):
            return txt2hex(self.dekKey)
        else:
            raise DaplugException(0x8000, "Invalid key number")

    def setKeyUsage(self, usage):
        """@KeySet.setKeyUsage"""
        self.usage = usage

    def getKeyUsage(self):
        """@KeySet.getKeyUsage"""
        return self.usage

    def setKeyAccess(self, access):
        """@KeySet.setKeyAccess"""
        self.access = access

    def getKeyAccess(self):
        """@KeySet.getKeyAccess"""
        return self.access
