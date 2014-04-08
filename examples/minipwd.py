import getpass
import time

from daplug.conv import *
from daplug.utils import *
from daplug.keyset import *
from daplug.keyboard import *
from daplug import *

"""
A minimalist password manager

Operating flow

main_menu
|-> Exit
|-> List devices
    |-> Back to menu
    |-> card #N
        |-> card_menu

card_menu
|-> Exit
|-> Change name
|-> Add password
    |-> Type password label
    |-> Type password
|-> Delete password
|-> Type password
    |-> Select password to type
        |-> Back
        |-> label #N
            |-> Typing password in 5 ... 1

Upgrade 1 : Protect with password
Upgrade 2 : Make keyboard layout configurable
Upgrade 3 : Allow password creation
"""

DEF_KEYS = KeySet(0x01, "404142434445464748494A4B4C4D4E4F")
SECU = DaplugDongle.C_MAC + DaplugDongle.C_DEC + DaplugDongle.R_MAC + DaplugDongle.R_ENC

NAME_F = 0x1001 # File containing the name of the card
DICO = 0x1002 # File containing a list of saved pwd and their file
DICO_S = 500 # Should be enough for ~20-30 passwords
KB_F = 0x0800 # Keyboard file

def typeSomething(dongle, phrase):
    size = 100
    delay = 3 # seconds
    dongle.selectFile(DaplugDongle.MASTER_FILE)
    try:
        dongle.createFile(KB_F, size, DaplugDongle.ACCESS_ALWAYS)
        dongle.selectFile(KB_F)
    except DaplugException:
        dongle.selectFile(KB_F)
    
    kb = KeyBoard()
    kb.addTextMac(phrase, azerty=1)
    kb.addReturn()
    kb.zeroPad(size)

    dongle.write(0, kb.getContent())
    dongle.useAsKeyboard()
    dongle.setKeyboardAtBoot(True)

    print("Typing in " + str(delay) + " seconds")
    def countdown(s):
        if s == 0:
            print("Typing !")
            dongle.triggerKeyboard()
            dongle.setKeyboardAtBoot(False)
        else:
            print(s)
            time.sleep(1)
            countdown(s-1)
    time.sleep(1)
    countdown(delay-1)

def formatSerial(serial):
    s = lst2hex(serial)
    v1 = str(int(s[30:32], 16))
    v2 = str(int(s[32:34], 16))
    v3 = "%02d" % int(s[34:36], 16)
    res = s[0:12] + " v" + v1 + "." + v2 + "." + v3
    return res

def unZeroPad(data):
    def aux(i):
        if i < 0:
            return ""
        if data[i] == '\x00':
            return aux(i-1)
        else:
            return data[:i]
    return aux(len(data)-1)

def listPasswords(dongle):
    res = {}
    dongle.selectFile(DaplugDongle.MASTER_FILE)
    try:
        dongle.selectFile(DICO)
        dico_cont = unZeroPad(lst2txt(dongle.read(0, DICO_S)))
        for couple in dico_cont.split('\xfd'):
            if couple != "":
                data = couple.split('\xfe')
                res[int(data[0], 16)] = data[1]
    except DaplugException:
        # No dico, create it
        dongle.createFile(DICO, DICO_S, DaplugDongle.ACCESS_ALWAYS)
        dongle.selectFile(DICO)
        dongle.write(0, "00"*DICO_S)
    return res

def resetDico(dongle):
    dongle.selectFile(DaplugDongle.MASTER_FILE)
    try:
        dongle.selectFile(DICO)
    except DaplugException:
        # No dico, create it
        dongle.createFile(DICO, DICO_S, DaplugDongle.ACCESS_ALWAYS)
        dongle.selectFile(DICO)
    dongle.write(0, "00"*DICO_S)

def saveDico(dongle, dico):
    dongle.selectFile(DaplugDongle.MASTER_FILE)
    try:
        dongle.selectFile(DICO)
    except DaplugException:
        # No dico, create it
        dongle.createFile(DICO, DICO_S, DaplugDongle.ACCESS_ALWAYS)
        dongle.selectFile(DICO)
    cont = ""
    for k in dico:
        cont += "%02x\xfe" % k + dico[k] + "\xfd"
    cont = cont + "\x00"*(DICO_S - len(cont))
    dongle.write(0, txt2hex(cont))

def savePass(dongle, nb, pwd):
    dongle.selectFile(DaplugDongle.MASTER_FILE)
    try:
        dongle.createFile(DICO+nb, len(pwd), DaplugDongle.ACCESS_ALWAYS)
    except DaplugException:
        # File exists, delete it
        dongle.deleteFileOrDir(DICO+nb)
        dongle.createFile(DICO+nb, len(pwd), DaplugDongle.ACCESS_ALWAYS)
    dongle.selectFile(DICO+nb)
    dongle.write(0, txt2hex(pwd))

def getPass(dongle, nb):
    dongle.selectFile(DaplugDongle.MASTER_FILE)
    dongle.selectFile(DICO+nb)
    return lst2txt(dongle.read(0, 0xEF))

def typePassword(dongle):
    dico = listPasswords(dongle)
    if len(dico) == 0:
        print("No password on card")
    else:
        print("Available password")
    print("0 - Back")
    for k in dico:
        print(str(k) + " - " + dico[k])
    choice = input("\nPlease select a password to type: ")
    if choice == 0:
        pass
    elif choice in dico:
        pwd = getPass(dongle, choice)
        typeSomething(dongle, pwd)
    else:
        println("Incorrect choice !")

def addPassword(dongle):
    print("Adding a password on the card")
    name = raw_input("\nType a name for this password: ")
    done = False
    while not done:
        pwd = getpass.getpass("Type the password: ")
        pwd2 = getpass.getpass("Retype password: ")
        if pwd == pwd2:
            dico = listPasswords(dongle)
            def aux(nb):
                if nb in dico:
                    aux(nb+1)
                else:
                    dico[nb] = name
                    saveDico(dongle, dico)
                    savePass(dongle, nb, pwd)
            aux(1)
            done = True
        else:
            print("Passwords are different !")
        
def showDongleMenu(dongle):
    serial = formatSerial(dongle.getSerial())
    dongle.authenticate(DEF_KEYS, SECU)
    done = False
    while not done:
        print("")
        print("Carte "+serial)
        print("0 - Back to card selection")
        print("1 - Add a password")
        print("2 - Type a password")
        print("3 - Reset card")
        choice = input("\nPlease select an action: ")
        if choice == 0:
            done = True
        elif choice == 1:
            addPassword(dongle)
        elif choice == 2:
            typePassword(dongle)
        elif choice == 3:
            resetDico(dongle)
        else:
            print("Invalid choice")

def noCard():
    print("")
    print("No card detected :")
    print("0 - Exit")
    print("1 - Rescan devices")
    return input("\nPlease select an action: ")

def showDeviceList(dongles):
    print("")
    print(str(len(dongles)) + " card(s) found")
    print("0 - Rescan devices")
    i = 1
    dongles2 = {}
    for (mode, device) in dongles:
        dongle = getDongle((mode, device))
        dongles2[i] = dongle
        serial = "Error retrieving serial"
        try:
            serial = formatSerial(dongle.getSerial())
        except DaplugException:
            pass
        print(str(i) + " - " + serial + " (mode " + mode + ")")
        i += 1
    choice = input("\nPlease select a card: ")
    if choice > 0 and choice <= len(dongles):
        dongle = dongles2[choice]
        showDongleMenu(dongle)

def runMainLoop():
    print(chr(27) + "[2J")
    done = False
    while not done:
        dongles = getDongleList()
        if len(dongles) == 0:
            choice = noCard()
            if choice == 0:
                print("Bye <3 !\n")
                done = True
        else:
            showDeviceList(dongles)

if __name__ == "__main__":
    runMainLoop()

    # listDevices()
    # pwd = getpass.getpass("Prout ? ")

    # print(pwd)

    # dongle = getFirstDongle()
    # dongle.authenticate(DEF_KEYS, SECU)
    # typeSomething(dongle, "Coucou")

