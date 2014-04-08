"""
Daplug keyboard file construction helper
"""

class KeyBoard:
    """@Keyboard"""

    def __init__(self):
        """@Keyboard.Keyboard"""
        self.content = ""

    def getContent(self):
        """@Keyboard.getContent"""
        return self.content

    def addOSProbe(self, nb=0x10, delay=0xFFFF, code=0x00):
        """@Keyboard.addOSProbe"""
        self.content += "1004" + "%02x" % nb + "%04x" % delay + "%02x" % code

    def addOSProbeWinR(self, nb=0x04, delay=0xFFFF, code=0x00):
        """@Keyboard.addOSProbeWinR"""
        self.content += "0204" + "%02x" % nb + "%04x" % delay + "%02x" % code

    def addIfPc(self):
        """@Keyboard.addIfPc"""
        self.content += "0E00"

    def addIfMac(self):
        """@Keyboard.addIfMac"""
        self.content += "0F00"

    def __addAsciiText(self, text):
        acc = ""
        for c in text:
            acc += "%02x" % ord(c)
        self.content += acc

    def addTextWindows(self, text):
        """@Keyboard.addTextWindows"""
        txtLen = len(text)
        if txtLen > 255:
            msg = "Text message too long"
            raise DaplugException(0x8021, msg)
        self.content += "04" + "%02x" % txtLen
        self.__addAsciiText(text)

    def addTextMac(self, text, azerty=False, delay=0x1000):
        """@Keyboard.addTextMac"""
        txtLen = len(text)
        if txtLen > 252:
            msg = "Text message too long"
            raise DaplugException(0x8021, msg)
        self.content += "11" + "%02x" % (txtLen + 3)
        az = 0
        if azerty:
            az = 1
        self.content += "%02x" % az + "%04x" % delay
        self.__addAsciiText(text)

    def addKeycodeRaw(self, code):
        """@Keyboard.addKeycodeRaw"""
        self.content += "09" + "%02x" % (len(code)/2) + code

    def addKeycodeRelease(self, code):
        """@Keyboard.addKeycodeRelease"""
        self.content += "03" + "%02x" % (len(code)/2) + code

    def addHotpCode(self, flag, digits, keyset, counterFile, div=None):
        data = "%02x" % flag + "%02x" % digits + "%02x" % keyset
        if div is not None:
            data += div
        data += "%04x" % counterFile
        l = len(data) / 2
        self.content += "50" + "%02x" % l + data

    def addReturn(self):
        """@Keyboard.addReturn"""
        self.content += "0D00"

    def addSleep(self, duration=0xFFFF):
        """@Keyboard.addSleep"""
        if (duration > 0xFFFF):
            self.content += "0104" + "%08x" % duration
        else:
            self.content += "0102" + "%04x" % duration

    def zeroPad(self, size):
        """@Keyboard.zeroPad"""
        curLen = len(self.content) / 2
        if curLen > size:
            msg = "Keyboard file too long"
            raise DaplugException(0x8020, msg)
        while (len(self.content) / 2 < size):
            self.content += "00"
