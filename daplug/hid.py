"""
Daplug HID communication module
"""

import usb1
import libusb1

from exception import DaplugException
from conv import *
from utils import dalog, zeroPad

class HIDDongle:

    def __init__(self, dongle):
        self.device = dongle.open()
        try:
            self.device.detachKernelDriver(0)
        except libusb1.USBError:
            pass
        try:
            self.device.detachKernelDriver(1)
        except libusb1.USBError:
            pass

    def getMode(self):
        return "hid"

    def exchange(self, apdu, status=0x9000, throwErr=True, name=""):
        # APDU in "hex" format
        dalog(name + " ==> " + apdu)
        paddedApdu = zeroPad(hex2txt(apdu))
        remaining = len(paddedApdu)
        offset = 0
        while (remaining > 0):
            self.device.interruptWrite(0x82, paddedApdu[offset:offset + 64])
            remaining -= 64
            offset += 64
        dataLength = 0
        result = self.device.interruptRead(0x82, 64)
        if result[0] == "\x61": # Response data available
            dataLength = ord(result[1])
            if dataLength > 62: # 64 bytes read, 2 extra bytes the first command
                remaining = dataLength - 62
                while remaining != 0:
                    if remaining > 64:
                        blockLength = 64
                    else:
                        blockLength = remaining
                    sub = self.device.interruptRead(0x82, 64)
                    result += sub
                    remaining = remaining - blockLength
            readSW = (ord(result[dataLength + 2]) << 8) + ord(result[dataLength + 3])
        else: # no response data available, read the SW immediately
            readSW =  (ord(result[0])  << 8) + ord(result[1])
        dalog(name + " <== (" + "%04x" % readSW + ") " + txt2hex(result[2:dataLength + 2]))
        if throwErr and readSW != status:
            raise DaplugException(readSW, "Invalid Status Word")
        return (txt2lst(result[2:dataLength + 2]), readSW)

    def close(self):
        self.device.close()

def listHID():
    context = usb1.USBContext()
    res = []
    for device in context.getDeviceList(skip_on_error=True):
        if device.getVendorID() == 0x2581 and device.getProductID() == 0x1807:
            res.append(device)
    return res

def __test(dongle):
    hid = HIDDongle(dongle)

    print "GET STATUS"
    hid.exchange("80F2400000")

    print "GET SERIAL NUMBER"
    hid.exchange("80E6000000")

    # Swith to USB
    hid.exchange("D052080200")
    # Reset
    hid.exchange("D052010000")
    hid.close()

def __main():
    dongles = listHID()
    if dongles != []:
        __test(dongles[0])
    else:
        print "No device found"

if __name__ == '__main__':
    __main()
