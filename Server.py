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

if __name__ == '__main__':
    app.run(host='0.0.0.0')
