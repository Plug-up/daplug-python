"""
Daplug exception module
"""

class DaplugException(Exception):
    """@DaplugException"""

    def __init__(self, code, message):
        """@DaplugException.DaplugException"""
        self.code = code
        self.message = message

    def __str__(self):
        ans = "Error: "
        ans = ans + ('%02x' % self.code)
        ans = ans + " (" + self.message + ")"
        return ans

    def message(self):
        """@DaplugException.message"""
        return self.message

    def code(self):
        """@DaplugException.code"""
        return self.code
