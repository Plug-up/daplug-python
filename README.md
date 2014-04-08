## daplug-python ##

Daplug Python APIs

### Requirements ###

This package was developped and tested with Python 2.7.2+

The only external dependency is [python-libusb1](https://github.com/vpelletier/python-libusb1.git) (developped and tested on version 1.1.0)

### Specific udev rule ###

You have to add a specific udev rule to allow access daplug USB devices. Create a file `/etc/udev/rules.d/10-daplug.rules`

    SUBSYSTEMS=="usb", ATTRS{idVendor}=="2581", ATTRS{idProduct}=="1807", MODE="0660", GROUP="daplug"
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="2581", ATTRS{idProduct}=="1808", MODE="0660", GROUP="daplug"

To restart udev run :

    sudo udevadm trigger

Then create a group `daplug` and add your account in it.

### Installation ###

Simply run `python setup.py install` (you may need root access to do this).