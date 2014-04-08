from daplug.conv import *
from daplug.utils import *
from daplug.keyset import *
from daplug.keyboard import *
from daplug import *

"""
A simple function to switch a card from HID to WinUSB mode
"""

def toHID(dongle):
    if dongle.getMode() == "usb":
        dongle.usb2hid()
        dongle.reset()

dongle = getFirstDongle()

toHID(dongle)
