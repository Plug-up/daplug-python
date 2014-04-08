"""
Daplug WinUSB communication module
"""

import usb1

from exception import DaplugException
from conv import *
from utils import dalog

class USBDongle:

    def __init__(self, dongle):
        self.device = dongle.open()
        self.interface = None
        self.endpoint = None
        for conf in dongle.iterConfigurations():
            i = 0
            for interf in conf.iterInterfaces():
                for setting in interf.iterSettings():
                    if self.interface is None and setting.getClass() == 255:
                        self.interface = i
                        for endpoint in setting.iterEndpoints():
                            if self.endpoint is None:
                                self.endpoint = endpoint.getAddress()
                i += 1
        if self.interface is None or self.endpoint is None:
            raise DaplugException(0x8888, "Invalid dongle")
        self.device.claimInterface(self.interface)

    def getMode(self):
        return "usb"

    def exchange(self, apdu, status=0x9000, throwErr=True):
        # APDU in "hex" format
        dalog("==> " + apdu)
        self.device.bulkWrite(self.endpoint, hex2txt(apdu))
        result = self.device.bulkRead(self.endpoint, 512)
        dataLength = 0
        if result[0] == "\x61": # response data available
            dataLength = ord(result[1])
            readSW = (ord(result[dataLength + 2]) << 8) + ord(result[dataLength + 3])
        else: # no response data available, read the SW immediately
            readSW = (ord(result[0]) << 8) + ord(result[1])
        dalog("<== (" + "%04x" % readSW + ") " + txt2hex(result[2:dataLength + 2]))
        if throwErr and readSW != status:
            raise DaplugException(readSW, "Invalid Status Word")
        return (txt2lst(result[2:dataLength + 2]), readSW)
        
    def close(self):
        self.device.close()

def listUSB():
    context = usb1.USBContext()
    res = []
    for device in context.getDeviceList(skip_on_error=True):
        if device.getVendorID() == 0x2581 and device.getProductID() == 0x1808:
            res.append(device)
    return res

def __test(dongle):
    print "Processing"
    usb = USBDongle(dongle)

    print "GET STATUS"
    usb.exchange("80F2400000")

    print "GET SERIAL NUMBER"
    usb.exchange("80E6000000")

    # Swith to HID
    usb.exchange("D052080100")
    usb.close()

def __main():
    dongles = listUSB()
    if dongles != []:
        __test(dongles[0])
    else:
        print "No device found"

if __name__ == '__main__':
    __main()
