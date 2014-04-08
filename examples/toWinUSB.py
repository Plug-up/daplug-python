from daplug.conv import *
from daplug.utils import *
from daplug.keyset import *
from daplug.keyboard import *
from daplug import *

"""
A simple function to switch a card from WinUSB to HID mode
"""

def toUSB(dongle):
    if dongle.getMode() == "hid":
        dongle.hid2usb()
        dongle.reset()

dongle = getFirstDongle()

toUSB(dongle)
