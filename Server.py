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

@app.route('/askfor', methods=['POST', 'GET'])
def ask_for_sth():
    """
    클라이언트에서 받은 요청에 따라 명령 수행
    :return: image path or stream address
    """
    order = request.args.get('order')
    if order == 'picture':
    # Todo:카메라 모듈로 사진 촬영 요청 그리고 이미지 경로 받아서 리턴
        return jsonify({'result': 'you ask for the current photograph'})
    elif order == 'movie':
    # Todo:동영상 촬영 및 스트리밍 주소 리턴
        return jsonify({'result': 'you ask for the current movie'})

@app.route('/login', methods=['POST'])
def validatePW():
    password = request.args.get('passwd')
    # import hashlib
    # pw = hashlib.md5()
    # pw.update("secret")
    # pw.digest()
    if password == 'secret':
        return jsonify({'result': 'Valid Password'})
    else:
        return jsonify({'result': 'Invalid Password'})

@app.route('/file')
def returnFilePath():
    return getFilePath()

@app.errorhandler(404)
def not_found():
    return jsonify({'result': 'please access the other path'})

@app.errorhandler(403)
def access_denied():
    return jsonify({'result': 'Access Denied'})

@app.errorhandler(500)
def server_problem_occurred():
    return jsonify({'result': 'Sorry, server problem occurred'})


def getFilePath():
    """
    this is a method to get specific file path.
    :return: file path
    """
    import os

    return os.path.curdir


if __name__ == '__main__':
    app.run(host='0.0.0.0')
