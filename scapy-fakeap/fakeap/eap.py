import threading


class EAPCode:
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4


class EAPType:
    IDENTITY = 1
    NOTIFICATION = 2
    NAK = 3
    MD5_CHALLENGE = 4
    OTP = 5
    GENERIC_TOKEN_CARD = 6
    EAP_TLS = 13
    EAP_LEAP = 17
    EAP_SIM = 18
    TTLS = 21
    PEAP = 25
    MSCHAP_V2 = 29
    EAP_CISCO_FAST = 43

    @classmethod
    def convert_type(cls, type_value):
        for key, value in vars(cls).iteritems():
            if value == type_value:
                return str(key)


class EAPHandler():
    def __init__(self):
        self.id = 0
        self.mutex = threading.Lock()

    def next_id(self):
        self.mutex.acquire()
        self.id = (self.id + 1)
        temp = self.id
        self.mutex.release()

        return temp

    def reset_id(self):
        self.mutex.acquire()
        self.id = 0
        self.mutex.release()