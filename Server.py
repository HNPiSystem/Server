# coding=utf-8
from multiprocessing import Process
from flask import Flask, request, jsonify, url_for, redirect
import random

app = Flask(__name__)


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
    jobs = {}

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
    # Todo: 내부에서 액세스토큰 생성하는 로직 필요
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
	f.close()

    def read_password(self):
	f = file('dat')
	s = f.read(4)
	f.close()
	print s
	return s

    def encrypt_pw(self):
        """
        This is a method to encrypt password.
        :param pw: assigned password.
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
        accesstkn = '%s%d%s%d' % (random.choice(randstr), random.randint(1, 10), random.choice(randstr), random.randint(1, 10))
        print accesstkn
        return accesstkn

    def set_proc_dic(self, pname, proc):
        self.jobs.update({pname: proc})

    def get_proc_dic(self):
        return self.jobs

    def terminate_proc(self, pname):
        if not pname == 'streaming' or pname == 'sensoring':
            self.jobs[pname].terminate()
            del self.jobs[pname]

# Login with password
@app.route('/')
def hello_world():
    return 'Welcome to HNPi System'


@app.route('/index')
def index():
    return redirect(url_for('hello_world'))


@app.route('/askfor', methods=['POST', 'GET'])
def ask_for_sth():
    """
    클라이언트에서 받은 요청에 따라 명령 수행.
    :return: image path or stream address
    """
    access_token = request.args.get('accessToken')
    if not x.is_valid_token(access_token):
        return jsonify({'result': 'you have invalid access token'})

    order = request.args.get('order')
    import camera   # 카메라 모듈 임포트.

    if order == 'picture':
        return jsonify({'result': '%s' % camera.camera_execute()})
    elif order == 'movie':
        p2 = Process(target=camera.view_stream, args=())
        p2.start()
        x.set_proc_dic('streaming', p2)
        import get_ip
        return jsonify({'result': 'rtsp://' + get_ip.get_ip_address('eth0') + ':8554/'})

@app.route('/suspend', methods=['GET'])
def suspend_sth():
    access_token = request.args.get('accessToken')
    if not x.is_valid_token(access_token):
        return jsonify({'result': 'you have invalid access token'})

    order = request.args.get('order')
    if order == 'sensor' and 'sensor' in x.get_proc_dic():
        x.terminate_proc('sensor')
        return jsonify({'result': 'Sensoring suspended'})
    elif order == 'streaming' and 'streaming' in x.get_proc_dic():
        x.terminate_proc('streaming')
        return jsonify({'result': 'Streaming suspended'})
    else:
        return jsonify({'result': 'Invalid request'})


@app.route('/login', methods=['POST', 'GET'])
def validatePW():
    """
    클라이언트에서 로그인 요청 시 패스워드 유효 판단 및 액세스 토큰 전달.
    :return: access_token
    """
    password = request.values.get('passwd')
    # Todo : 외부에서 설정한 패스워드로 지정
    print password
    if password == x.encrypt_pw():
        atoken = x.getAccessToken()
        return jsonify({'result': '%s' % atoken})
    else:
        return jsonify({'result': 'Invalid Password %s' % password})


if __name__ == '__main__':
    import sys
    sys.path.append("/home/pi/Hardware_Module/Hardware")
    import pir_sensor

    x = NetworkManager()
    # p = Process(target=pir_sensor.sensoring, args=())
    # p.start()
    # x.set_proc_dic('sensoring', p)

    app.run(host='0.0.0.0', port=5000, debug=True)
