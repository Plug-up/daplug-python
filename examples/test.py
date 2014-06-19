from daplug.conv import *
from daplug.utils import *
from daplug.keyset import *
from daplug.keyboard import *
from daplug import *

"""
Code samples for Daplug cards

Some tests may not pass if you do not have the right licenses on your cards
"""

defKeys = KeySet(0x01, "404142434445464748494A4B4C4D4E4F")
newKeys = KeySet(0x87, "000102030405060708090A0B0C0D0E0F", "101112131415161718191A1B1C1D1E1F", "202122232425262728292A2B2C2D2E2F")
newKeys.setKeyAccess(0x0001)
newKeys.setKeyUsage(KeySet.USAGE_GP)

secu01 = DaplugDongle.C_MAC
secu03 = DaplugDongle.C_MAC + DaplugDongle.C_DEC
secu11 = DaplugDongle.C_MAC + DaplugDongle.R_MAC
secu13 = DaplugDongle.C_MAC + DaplugDongle.C_DEC + DaplugDongle.R_MAC
secu33 = DaplugDongle.C_MAC + DaplugDongle.C_DEC + DaplugDongle.R_MAC + DaplugDongle.R_ENC

def h1(msg):
    print(" ###################### ")
    print(" ##### " +msg + " ##### ")
    print(" ###################### ")

def title(msg):
    print(" ~~~~~ " +msg + " ~~~~~ ")

def testBasic(dongle):
    # print("Status: " + lst2hex(dongle.getStatus()))
    print("Serial: " + lst2hex(dongle.getSerial()))

def testOneSC(dongle, secu, keys):
    title("Test SC with security: " + "%02x" % secu)
    dongle.authenticate(keys, secu)
    print("Serial: " + lst2hex(dongle.getSerial()))
    print("Serial: " + lst2hex(dongle.getSerial()))
    dongle.deAuthenticate(keys.version)

def testSC(dongle):
    h1("Test Secure Channel")
    testOneSC(dongle, secu01, defKeys)
    testOneSC(dongle, secu03, defKeys)
    testOneSC(dongle, secu11, defKeys)
    testOneSC(dongle, secu13, defKeys)
    testOneSC(dongle, secu33, defKeys)

def testPutKey(dongle):
    h1("Test Put Key")
    title("Authenticate")
    dongle.authenticate(defKeys, secu13)

    title("Putting new key")
    dongle.putKey(newKeys)

    dongle.deAuthenticate(defKeys.version)
    title("Testing new key")
    testOneSC(dongle, secu01, newKeys)

    title("Cleanup")
    dongle.deAuthenticate(newKeys.version)
    dongle.authenticate(defKeys, secu13)
    dongle.deleteKey(newKeys.version)
    dongle.deAuthenticate(defKeys.version)

def testFiles(dongle):
    h1("Test Files")
    text = "abbe1acceda1accede1accede1baba1baffe1baffee1ba0bab1bebe1b0b01caca1cacaba1cacabe1caca01cade1cafe1ceda1cede1cedee1c0bea1c0ca1c0c01c0da1c0dee1dada1deca1decade1decede1decedee1dec0da1dec0de1dec0dee1d0d01ecaffa1ecaffe1ecaffe1ecaffee1eccaca1efface1effacee1facade1face1faceaface1fada1fade1fadee1fad01abbe1acceda1accede1accede1baba1baffe1baffee1ba0bab1bebe1b0b01caca1cacaba1cacabe1caca01cade1cafe1ceda1cede1cedee1c0bea1c0ca1c0c01c0da1c0dee1dada1deca1decade1decede1decedee1dec0da1dec0de1dec0dee1d0d01ecaffa1ecaffe1ecaffe1ecaffee1eccaca1efface1effacee1facade1face1faceaface1fada1fade1fadee1fad01abbe1acceda1accede1accede1baba1baffe1baffee1ba0bab1bebe1b0b01caca1cacaba1cacabe1caca01cade1cafe1ceda1cede1cedee1c0bea1c0ca1c0c01c0da1c0dee1dada1deca1decade1decede1decedee1dec0da1dec0de1dec0dee1d0d01ecaffa1ecaffe1ecaffe1ecaffee1eccaca1efface1effacee1facade1face1faceaface1fada1fade1fadee1fad01abbe1acceda1accede1accede1baba1baffe1baffee1ba0bab1bebe1b0b01caca1cacaba1cacabe1caca01cade1cafe1ceda1cede1cedee1c0bea1c0ca1c"
    title("Authenticate")
    dongle.authenticate(defKeys, secu01)
    title("Create and select dir 2012")
    dongle.createDir(0x2012, DaplugDongle.ACCESS_ALWAYS)
    dongle.selectFile(0x2012)
    title("Create and select dir 2013")
    dongle.createDir(0x2013, DaplugDongle.ACCESS_ALWAYS)
    dongle.selectFile(0x2013)
    title("Go up and clean")
    dongle.selectFile(0x2012)
    dongle.deleteFileOrDir(0x2013)
    title("Create and select file 2014")
    dongle.createFile(0x2014, 500, DaplugDongle.ACCESS_ALWAYS)
    dongle.selectFile(0x2014)
    title("Write file")
    dongle.write(0, text)
    title("Read file")
    print("READ: " + lst2hex(dongle.read(0, 500)))
    title("Go up and clean")
    dongle.selectFile(0x2012)
    dongle.deleteFileOrDir(0x2014)
    title("Go up (MF) and clean")
    dongle.selectFile(DaplugDongle.MASTER_FILE)
    dongle.deleteFileOrDir(0x2012)
    title("Done")
    dongle.deAuthenticate(defKeys.version)

def testCrypto(dongle):
    h1("Test Crypto")
    title("Authenticate")
    dongle.authenticate(defKeys, secu01)
    title("Setting a key for crypto")
    cryptKey = KeySet(0x7b, "404142434445467848494A4B4C4D4E4F")
    cryptKey.setKeyAccess(0x0000)
    cryptKey.setKeyUsage(KeySet.USAGE_ENC_DEC)
    dongle.putKey(cryptKey)

    title("Encrypting a test message in CBC without IV")
    message = "B00B5B00B5B00B50"
    mode = DaplugDongle.CRYPT_CBC
    iv = "0123456789ABCDEF"
    div = "0123456789ABCDEF"*2
    ans1 = lst2hex(dongle.encrypt(0x7b, 0x01, mode, message, iv=iv, div1=div))
    print("ENC: " + message + " -> " + ans1)
    title("Decrypting test message")
    ans2 = lst2hex(dongle.decrypt(0x7b, 0x01, mode, ans1, iv=iv, div1=div))
    print("DEC: " + ans1 + " -> " + ans2)

    title("Encrypting a test message in ECB")
    message = "B00B5B00B5B00B50"
    mode = DaplugDongle.CRYPT_ECB
    ans1 = lst2hex(dongle.encrypt(0x7b, 0x01, mode, message))
    print("ENC: " + message + " -> " + ans1)
    title("Decrypting test message")
    ans2 = lst2hex(dongle.decrypt(0x7b, 0x01, mode, ans1))
    print("DEC: " + ans1 + " -> " + ans2)

    title("Cleanup")
    dongle.deleteKey(cryptKey.version)
    dongle.deAuthenticate(defKeys.version)

def testHMAC(dongle):
    h1("Test HMAC")
    title("Authenticate")
    dongle.authenticate(defKeys, secu01)

    hmacKey = KeySet(0x03, "404142434445467848494A4B4C4D4E4F")
    hmacKey.setKeyAccess(0x0001)
    hmacKey.setKeyUsage(KeySet.USAGE_HMAC_SHA1)

    title("Try clean")
    try:
        dongle.deleteKeys([hmacKey.version])
    except DaplugException:
        pass

    title("Setting a key for HMAC")
    dongle.putKey(hmacKey)

    title("Testing HMAC")
    data = "DECADE20"
    ans = dongle.hmac(hmacKey.version, 0x00, data)
    print(lst2hex(ans))

    title("Cleanup")
    dongle.deleteKey(hmacKey.version)
    dongle.deAuthenticate(defKeys.version)

def testHOTP(dongle):
    hotpKeyVersion = 0x03
    hotpKey = "716704022D872983665A03E6C39EC117C084228A"
    h1("Test HOTP")
    title("Authenticate")
    dongle.authenticate(defKeys, secu01)

    title("Try clean")
    print "Clean HOTP key ..."
    try:
        dongle.deleteKeys([hotpKeyVersion])
    except DaplugException:
        pass
    print "Clean HID mapping file ..."
    try:
        dongle.selectFile(0x3F00)
        dongle.deleteFileOrDir(0x0001)
    except DaplugException:
        pass
    print "Clean counter file ..."
    try:
        dongle.selectFile(0xC010)
        dongle.deleteFileOrDir(0x42)
    except DaplugException:
        pass


    title("Setting a key for HOTP")
    keyLen = len(hotpKey) / 2
    keys = splitKey(hotpKey)
    hotpKey = KeySet(hotpKeyVersion, keys[0], keys[1], keys[2])
    hotpKey.setKeyAccess(0x0000 + keyLen)
    hotpKey.setKeyUsage(KeySet.USAGE_HOTP)
    dongle.putKey(hotpKey)

    title("Creating a counter file")
    dongle.createCounterFile(0x42)

    title("Creating the HID mapping file - not sure if really useful...")
    dongle.selectFile(0x3F00)
    dongle.createFile(0x0001, 16, DaplugDongle.ACCESS_ALWAYS)
    dongle.write(0, "06050708090a0b0c0d0e0f1115171819")

    data = "%04x" % 0x42
    title("Testing HOTP with file " + data)
    dongle.selectPath([0x3F00])
    totp1 = dongle.hmac(hotpKey.version, DaplugDongle.OTP_6_DIGIT + DaplugDongle.HOTP_DATA_FILE, data)
    totp2 = dongle.hmac(hotpKey.version, DaplugDongle.OTP_6_DIGIT + DaplugDongle.HOTP_DATA_FILE, data)

    title("Cleanup")
    dongle.deAuthenticate(defKeys.version)

    print "Generated TOTP: " + lst2txt(totp1)
    print "Generated TOTP: " + lst2txt(totp2)

def testTOTP(dongle):
    timeKeyVersion = 0x04
    timeKey = "505152535455565758595A5B5C5D5E5F"
    totpKeyVersion = 0x05
    base32Key = "oftq iarn q4uy gzs2 aptm hhwb c7ai iiuk"

    h1("Test TOTP")
    title("Authenticate")
    dongle.authenticate(defKeys, secu01)

    title("Try clean")
    try:
        dongle.deleteKeys([0x02, 0x03, timeKeyVersion, totpKeyVersion])
    except DaplugException:
        pass

    title("Setting a time key")
    dongle.setTotpTimeKey(timeKeyVersion, timeKey)

    title("Setting a TOTP key")
    dongle.setTotpKeyBase32(totpKeyVersion, timeKeyVersion, base32Key)

    title("Setting time")
    dongle.setTimeOTP(timeKeyVersion, 0x01, timeKey)

    title("Getting TOTP")
    totp = dongle.totp(totpKeyVersion, DaplugDongle.OTP_6_DIGIT)

    title("Cleanup")
    dongle.deleteKeys([timeKeyVersion, totpKeyVersion])
    dongle.deAuthenticate(defKeys.version)
    print "Generated TOTP: " + totp

def toggleMode(dongle):
    if dongle.getMode() == "usb":
        dongle.usb2hid()
    else:
        dongle.hid2usb()
    dongle.reset()
    time.sleep(1)

def testRight(dongle):
    title("Test Rights")
    dongle.selectPath([0x3F00, 0xC00F, 0xD00D, 0xA1BA])
    print("READ: " + lst2hex(dongle.read(0, 2)))
    dongle.authenticate(defKeys, secu01)
    print("READ: " + lst2hex(dongle.read(0, 2)))

dongle = getFirstDongle()
print "Found " + dongle.getMode() + " device"
# testBasic(dongle)
dongle.setKeyboardAtBoot(False)

# testRight(dongle)

# testSC(dongle)
# testPutKey(dongle)
# testFiles(dongle)
# testCrypto(dongle)
# testHMAC(dongle)
# testHOTP(dongle)
# testTOTP(dongle)

# toggleMode(dongle)
