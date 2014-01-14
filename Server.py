# coding=utf-8
from flask import Flask, request, jsonify
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
    :return: result of request
    """

    global exe_flag

    access_token = request.args.get('accessToken')
    if not netManager.is_valid_token(access_token):
        return jsonify({'result': 'you have invalid access token'})

    order = request.args.get('order')

    if order == 'movie':                                                # 스트리밍 요청
        hdManager.ask_streaming()
        return jsonify({'result': 'rtsp://119.197.164.6:8554/'})

    elif order == 'pir_on':                                             # 인체감지센서 On
        hdManager.ask_pir_sensor()
        return jsonify({'result': 'PIR Sensoring...'})

    elif order == 'pir_off':                                            # 인체감지센서 Off
        hdManager.terminate_proc('pir')
        return jsonify({'result': 'PIR Sensor Off'})

    elif order == 'therm':                                              # 현재 온도 체크
        # Send the current temperature.
        return jsonify({'result': hdManager.ask_thermo_sensor()})

    elif order == 'light_auto_on':                                      # Auto light 센서 On
        if not hdManager.ask_light_sensor() == -1:
            return jsonify({'result': 'Light Auto Mode'})

    elif order == 'light_auto_off':                                     # Auto light 센서 Off
        hdManager.terminate_proc('light')
        return jsonify({'result': 'Light Auto Off'})

    elif order == 'light_on':                                           # light On
        result = hdManager.ask_light_relay_on()
        if result == 'True':
            return jsonify({'result': 'Turned On'})
        elif result == 'False':
            return jsonify({'result': 'Error : Not turned on'})
        else:
            return jsonify({'result': 'System Error'})

    elif order == 'light_off':                                          # light Off
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
        access_token = netManager.getAccessToken()
        available_deivce_list = hdManager.get_status_of_devices()
        print devices
        return jsonify({'result': '%s' % access_token, 'devices': available_deivce_list})
    else:
        return jsonify({'result': 'Invalid Password'})


@app.route('/password', methods=['POST'])
def changePW():
    """
    클라이언트에서 패스워드 변경 요청 시 패스워드 유효 판단 및 새 패스워드로 변경.
    이후 결과로서 조건에 따라 메세지를 전송.
    :return: message as condition
    """
    password = request.args.get('passwd')
    if password == netManager.getPassword():
        new_pw = request.args.get('new_pw')
        netManager.write_password(new_pw)
        return jsonify({'result': 'Success'})
    else:
        return jsonify({'result': 'PW is not correct'})


if __name__ == '__main__':
    netManager = NetworkManager.NetworkManager()            # NetworkManager 생성 및 초기화.
    import sys

    sys.path.append("/home/pi/Hardware_Module/Hardware")    # system 환경 변수에 경로 추가.

    import Hardware                                         # Hardware 컨트롤를 위한 모듈 import.

    hdManager = Hardware.HardwareManager()                  # HardwareManager 생성 및 초기화.
    devices = hdManager.get_status_of_devices()             # 현재 연결 된 디바이스 체크 및
    netManager.set_devices(devices)                         # 디바이스 셋을 NetworkManager에 설정

    app.run(host='0.0.0.0', port=5000, debug=True)
