"""
Daplug Conversion functions

Whe will name three formats for data :
  - hex : "6E"
  - lst : [110]
  - txt : "n"

User functions generally take and return data in the "hex" format.
Low level functions generally use the "txt" format.
The "lst" format is often used by legacy functions (it may eventually
disappear).
"""

def hex2txt(data):
    res = ""
    x = 0
    while x < len(data):
        res += chr(int(data[x:x + 2], 16))
        x += 2
    return res

def hex2lst(data):
    res = []
    x = 0
    while x < len(data):
        res.append(int(data[x:x + 2], 16))
        x += 2
    return res


def txt2lst(data):
    res = []
    for c in data:
        res.append(ord(c))
    return res

def txt2hex(data):
    res = ""
    for c in data:
        res += "%02x" % ord(c)
    return res


def lst2hex(data):
    res = ""
    for i in data:
        res += '%02x' % i
    return res

def lst2txt(data):
    res = ""
    for i in data:
        res += chr(i)
    return res
