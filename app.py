from flask import Flask, request, jsonify, send_from_directory
import json, os
from script import start_background_scan, stop_background_scan, scan_network, load_config, save_config

app = Flask(__name__)
CONFIG_PATH = "config.json"

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/style.css')
def css():
    return send_from_directory('.', 'style.css')

@app.route('/submit', methods=['POST'])
def submit():
    data = request.get_json()
    config = {
        "subnet": data.get("subnet", "").strip(),
        "known_mac": [mac.strip() for mac in data.get("known_mac", []) if mac.strip()],
        "known_ip": [ip.strip() for ip in data.get("known_ip", []) if ip.strip()]
    }
    try:
        save_config(config)
        return jsonify({"message": "Настройки успешно сохранены!"})
    except Exception as e:
        return jsonify({"message": f"Ошибка: {str(e)}"}), 500


@app.route('/scan', methods=['GET'])
def scan():
    start_background_scan()
    return jsonify({"status": "Сканирование запущено."})

@app.route('/stop_scan', methods=['GET'])
def stop():
    stop_background_scan()
    return jsonify({"status": "Сканирование остановлено."})

if __name__ == '__main__':
    app.run(debug=True)
