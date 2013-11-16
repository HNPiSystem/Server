# coding=utf-8
from flask import Flask, request, jsonify, url_for, redirect

app = Flask(__name__)

# class NetworkMng:
#     def __init__(self, passwd):
#         self.passwd = passwd
#     def getPasswd(self):
#         return self.passwd

# Login with password
@app.route('/')
def hello_world():
    return 'Welcome to HNPi System'

@app.route('/index')
def index():
    return redirect(url_for('hello_world'))


def is_valid_token(access_token):
    # Todo: 내부에서 액세스토큰 생성하는 로직 필요
    """
    this is a method to validate access token.
    :param access_token: the access token which is sent by client.
    :return: True or False
    """
    if access_token == 'accessToken':
        return True
    else:
        return False


@app.route('/askfor', methods=['POST', 'GET'])
def ask_for_sth():
    """
    클라이언트에서 받은 요청에 따라 명령 수행.
    :return: image path or stream address
    """
    access_token = request.args.get('accessToken')
    if not is_valid_token(access_token):
        return jsonify({'result': 'you have invalid access token'})

    order = request.args.get('order')
    if order == 'picture':
    # Todo:카메라 모듈로 사진 촬영 요청
        import getUrl
        return jsonify({'picture': '%s' % getUrl.getURL()})
    elif order == 'movie':
    # Todo:동영상 촬영 및 스트리밍 주소 리턴
        return jsonify({'result': 'you ask for the current movie'})

@app.route('/login', methods=['POST'])
def validatePW():
    """
    클라이언트에서 로그인 요청 시 패스워드 유효 판단 및 액세스 토큰 전달.
    :return: access_token
    """
    password = request.args.get('passwd')
    # import hashlib
    # pw = hashlib.md5()
    # pw.update("secret")
    # pw.digest()
    # Todo : 외부에서 설정한 패스워드로 지정
    # Todo : 액세스 토큰 생성해서 전달하도록 구현
    if password == 'secret':
        return jsonify({'result': 'Valid Password'})
    else:
        return jsonify({'result': 'Invalid Password'})


if __name__ == '__main__':
    app.run(host='0.0.0.0')
