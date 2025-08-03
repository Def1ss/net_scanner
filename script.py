import os, json, time, threading
import ipaddress
import scapy.all as sc
import netifaces

CONFIG_PATH = "config.json"
DEFAULT_SUBNET = "192.168.0.0/24"
DEFAULT_CONFIG = {"SUBNET": "", "KNOWN_DEVICES": []}
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ARP_TIMEOUT = 2
SCAN_INTERVAL = 300
SCAN_ATTEMPTS = 5

scan_thread = None
stop_event = threading.Event()

def get_network_range():
    try:
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        ip = info['addr']
        netmask = info['netmask']
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except Exception:
        return DEFAULT_SUBNET

def get_ip_mac_network(ip_range):
    answered, _ = sc.srp(
        sc.Ether(dst=BROADCAST_MAC) / sc.ARP(pdst=ip_range),
        timeout=ARP_TIMEOUT, verbose=False
    )
    return [{'ip': rcv.psrc, 'mac': rcv.hwsrc} for _, rcv in answered]

def deduplicate(devices):
    seen = set()
    result = []
    for d in devices:
        key = (d['ip'], d['mac'])
        if key not in seen:
            seen.add(key)
            result.append(d)
    return result

def load_config():
    if not os.path.exists(CONFIG_PATH):
        print("Файл конфигурации не найден. Создаю новый...")
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = json.load(f)

        if not isinstance(config, dict):
            raise ValueError("Конфигурация должна быть словарём.")

        if "KNOWN_DEVICES" not in config or not isinstance(config["KNOWN_DEVICES"], list):
            print("Поле KNOWN_DEVICES повреждено. Восстанавливаю...")
            config["KNOWN_DEVICES"] = []

        if "SUBNET" not in config or not isinstance(config["SUBNET"], str):
            print("Поле SUBNET повреждено. Восстанавливаю...")
            config["SUBNET"] = ""

        return config

    except (json.JSONDecodeError, ValueError) as e:
        print(f"Ошибка загрузки config.json: {e}. Восстанавливаю конфигурацию...")
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG

def save_config(config):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

def update_known_devices(devices):
    config = load_config()
    known = config.get("KNOWN_DEVICES", [])
    known_macs = {d["mac"] for d in known}
    new = [d for d in devices if d["mac"] not in known_macs]
    if new:
        config["KNOWN_DEVICES"].extend(new)
        save_config(config)
        print("Добавлены новые устройства:")
        for d in new:
            print(f"IP: {d['ip']}, MAC: {d['mac']}")

def scan_network(attempts=SCAN_ATTEMPTS):
    config = load_config()
    subnet = config.get("SUBNET") or get_network_range()
    devices = []
    for _ in range(attempts):
        devices.extend(get_ip_mac_network(subnet))
    return deduplicate(devices)

def background_scan_loop():
    while not stop_event.is_set():
        print("Запуск сканирования...")
        devices = scan_network()
        update_known_devices(devices)
        time.sleep(SCAN_INTERVAL)

def start_background_scan():
    global scan_thread
    if scan_thread and scan_thread.is_alive():
        return
    stop_event.clear()
    scan_thread = threading.Thread(target=background_scan_loop)
    scan_thread.start()

def stop_background_scan():
    stop_event.set()
