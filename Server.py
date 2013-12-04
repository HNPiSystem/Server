# coding=utf-8
from multiprocessing import Process
from flask import Flask, request, jsonify, url_for, redirect

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

    def __init__(self, passwd):
        self.password = passwd
        self.access_token = self.get_access_token()

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

    # def encrypt_pw(self, pw):
    #     """
    #     This is a method to encrypt password.
    #     :param pw: assigned password.
    #     :return: encrypted password.
    #     """
    #     import hashlib
    #     pw = hashlib.md5()
    #     pw.update(x.getPassword())
    #     return pw.digest()

    def get_access_token(self):
        """
        This is a method to create an access token for request
        :rtype : str
        :return: access_token
        """
        # Todo : 서버가 실행될 때 무작위적으로 액세스토큰을 만드는 로직이 필요 ; 현재 일시적으로 'accessToken' 문자열 리턴
        # Todo : 만든 액세스토큰은 서버 내에서 변수로 저장해야 함
        return 'accessToken'


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
        return jsonify({'result': 'rtsp://119.197.164.6:8554/'})


@app.route('/login', methods=['POST', 'GET'])
def validatePW():
    """
    클라이언트에서 로그인 요청 시 패스워드 유효 판단 및 액세스 토큰 전달.
    :return: access_token
    """
    password = request.args.get('passwd')
    # encrypted_pw = get_encrypted_pw()
    # Todo : 외부에서 설정한 패스워드로 지정

    # access_token = get_access_token()
    atoken = x.getAccessToken()
    if password == '1234':
        return jsonify({'result': '1234 %s' % atoken})
    else:
        return jsonify({'result': 'Invalid Password'})




if __name__ == '__main__':
    x = NetworkManager(1234)
    import pir_sensor
    p = Process(target=pir_sensor.sensoring, args=())
    p.start()
    app.run(host='0.0.0.0', port=5000)
