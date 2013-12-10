# coding=utf-8
from multiprocessing import Process
from flask import Flask, request, jsonify, url_for, redirect
import NetworkManager

app = Flask(__name__)

# Login with password
@app.route('/')
def hello_world():
    return 'Welcome to HNPi System'


@app.route('/askfor', methods=['POST', 'GET'])
def ask_for_sth():
    """
    클라이언트에서 받은 요청에 따라 명령 수행.
    :return: image path or stream address
    """
    access_token = request.args.get('accessToken')
    if not netManager.is_valid_token(access_token):
        return jsonify({'result': 'you have invalid access token'})

    order = request.args.get('order')

    if order == 'movie':
        hdManager.ask_streaming()
        import get_ip

        return jsonify({'result': 'rtsp://' + get_ip.get_ip_address('eth0') + ':8554/'})

    elif order == 'pir_on':
        hdManager.ask_pir_sensor()
        return jsonify({'result': 'PIR Sensoring...'})

    elif order == 'pir_off':
        hdManager.termniate_proc('pir')
        return jsonify({'result': 'PIR Sensor Off'})

    elif order == 'therm':
        # 현재 온도 체크해서 보내 줌.
        return jsonify({'result': hdManager.ask_thermo_sensor()})

    elif order == 'light_auto_on':
        if not hdManager.ask_light_relay_auto == -1:
            return jsonify({'result': 'light Auto Mode'})

    elif order == 'light_auto_off':
        hdManager.termniate_proc('light')
        return jsonify({'result': 'Light Auto Off'})

    elif order == 'light_on':
        result = hdManager.ask_light_relay_on()
        if result == 'True':
            return jsonify({'result': 'Turned On'})
        elif result == 'False':
            return jsonify({'result': 'Error : Not turned on'})
        else:
            return jsonify({'result': 'System Error'})

    elif order == 'light_off':
        result = hdManager.ask_light_relay_off()
        if result == 'True':
            return jsonify({'result': 'Turned Off'})
        elif result == 'False':
            return jsonify({'result': 'Error : Not turned off'})
        else:
            return jsonify({'result': 'System Error'})


@app.route('/login', methods=['POST', 'GET'])
def validatePW():
    """
    클라이언트에서 로그인 요청 시 패스워드 유효 판단 및 액세스 토큰 전달.
    현재 연결 가능한 디바이스 정보들을 가져와 클라이언트로 보내준다.
    :return: access_token, available_deivce_list
    """
    # Todo : 이용 가능한 디바이스 목록 불러오기
    password = request.values.get('passwd')

    if password == netManager.getPassword():
        atoken = netManager.getAccessToken()
        return jsonify({'result': '%s' % atoken, 'devices': netManager.available_dev_list()})
    else:
        return jsonify({'result': 'Invalid Password %s' % password})


@app.route('/password', methods=['POST'])
def changePW():
    password = request.args.get('passwd')
    if password == netManager.getPassword():
        new_pw = request.args.get('new_pw')
        netManager.write_password(new_pw)
        return jsonify({'result': 'Success'})
    else:
        return jsonify({'result': 'PW is not correct'})


if __name__ == '__main__':
    netManager = NetworkManager.NetworkManager()
    import sys

    sys.path.append("/home/pi/Hardware_Module/Hardware")

    import Hardware
    hdManager = Hardware.HardwareManager()
    devices = hdManager.get_status_of_devices()
    netManager.set_devices(devices)

    app.run(host='0.0.0.0', port=5000, debug=True)
