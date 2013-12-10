import random


def singleton(class_):
    class class_w(class_):
        _instance = None

        def __new__(cls, *args, **kwargs):
            if class_w._instance is None:
                class_w._instance = super(class_w, cls).__new__(cls, *args, **kwargs)
                class_w._instance._sealed = False
            return class_w._instance

        def __init__(self, *args, **kwargs):
            if self._sealed:
                return
            super(class_w, self).__init__(*args, **kwargs)
            self._sealed = True

    class_w.__name__ = class_.__name__
    return class_w


@singleton
class NetworkManager(object):
    """
    This is the network Manager class to manage the access token, system login password.
    """
    password = ''
    access_token = ''
    devices = []

    def __init__(self):
        self.password = self.read_password()
        self.access_token = self.create_access_token()

    @classmethod
    def name(cls):
        print cls.__name__

    def getPassword(self):
        return self.password

    def getAccessToken(self):
        return self.access_token

    def is_valid_token(self, atoken):
        """
        This is a method to validate access token.
        :param atoken: the access token which is sent by client.
        :return: True or False
        """
        if atoken == self.getAccessToken():
            return True
        else:
            return False

    def write_password(self, pw):
        f = file('dat', 'w+')
        f.write(pw)
        self.password = pw
        f.close()

    def read_password(self):
        f = file('dat')
        s = f.read(32)
        f.close()
        print s
        return s

    def encrypt_pw(self):
        """
        This is a method to encrypt password.
        :return: encrypted password.
        """
        import hashlib

        pw = hashlib.md5()
        pw.update(self.password)
        result = pw.hexdigest()
        return result

    def create_access_token(self):
        """
        This is a method to create an access token for request
        :rtype : str
        :return: access_token
        """
        randstr = ['a', 'b', 'c', 'd', 'e', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'e', 'l', 'm', 'o']
        accesstkn = '%s%d%s%d' % (
            random.choice(randstr), random.randint(1, 10), random.choice(randstr), random.randint(1, 10))
        print accesstkn
        return accesstkn

    def set_devices(self, deivces):
        self.devices = deivces

    def get_devices_list(self):
        return self.devices

