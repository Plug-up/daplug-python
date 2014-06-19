from daplug.conv import *
from daplug.sam import *
from daplug.utils import *
from daplug.keyset import *
from daplug.keyboard import *
from daplug import *

"""
Code sample to test Daplug SAM

This test requires one dongle with the COMMUNITY_KEYSET right in HID mode
and another one in WinUSB mode
"""

secu = DaplugDongle.C_MAC + DaplugDongle.C_DEC + DaplugDongle.R_MAC + DaplugDongle.R_ENC

def h1(msg):
    print(" ######" + "#"*len(msg) + "###### ")
    print(" ##### " +msg + " ##### ")
    print(" ######" + "#"*len(msg) + "###### ")

def title(msg):
    print(" ~~~~~ " +msg + " ~~~~~ ")

def simpleCommands(dongle):
    h1("Testing simple commands")
    print("Serial: " + lst2hex(dongle.getSerial()))
    print("Serial: " + lst2hex(dongle.getSerial()))
    title("Simple commands test OK")

def test():
    h1("Running SAM test")

    devices = getDongleList()

    dongle = None
    sam = None

    for (mode, device) in devices:
        if (mode == "hid") & (sam is None): sam = DaplugSAM(getDongle((mode, device), "SAM"))
        if (mode == "usb") & (dongle is None): dongle = getDongle((mode, device), "CARD")

    if (sam is None):
        title("No SAM dongle!")
        raise Exception("No SAM dongle!")

    if (dongle is None):
        title("No target dongle!")
        raise Exception("No dongle!")

    title("Sam and target found")

    h1("Connecting with community keyset")

    # Community keyset
    samCtxKeyVersion = 0xFC
    samCtxKeyID = 1
    samGPKeyVersion = 0x66
    cardKeyVersion = 0x42

    mode = DaplugSAM.DIV1 + DaplugSAM.GENERATE_DEK + DaplugSAM.GENERATE_RMAC + DaplugSAM.GENERATE_RENC

    chipDiv = dongle.getChipDiversifier()

    dongle.authenticateSam(sam, samCtxKeyVersion, samCtxKeyID, samGPKeyVersion, cardKeyVersion, secu, chipDiv)

    title("SAM auth with community keyset OK")
    
    simpleCommands(dongle)

test()
