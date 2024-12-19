import serial
import serial.tools.list_ports
import time
import sys

def get_serial_ports():
    return [port.device for port in serial.tools.list_ports.comports()]

# 提示用户拔掉所有串口设备
input("请拔掉所有串口设备后按回车继续...")

# 获取当前串口列表
initial_ports = set(get_serial_ports())

# 提示用户插入串口设备
print("请在5秒内插入串口设备...")
time.sleep(5)

# 获取新的串口列表
new_ports = set(get_serial_ports())

# 找出新增的串口
added_ports = new_ports - initial_ports

if len(added_ports) == 0:
    print("未检测到新的串口设备。")
    sys.exit(1)
elif len(added_ports) > 1:
    print("检测到多个新的串口设备，请手动指定串口号。")
    sys.exit(1)
else:
    port = added_ports.pop()
    print(f"检测到新的串口设备: {port}")

# 获取用户输入
input_str = input("请输入SN和WiFi MAC，格式为<sn>;<wifi mac>：")

# 解析输入，获取SN和WiFi MAC
try:
    sn, wifi_mac = input_str.strip().split(';')
    sn = sn.lower()
    wifi_mac = wifi_mac.lower()
except ValueError:
    print("输入格式错误，应为<sn>;<wifi mac>")
    sys.exit(1)

# 计算蓝牙MAC地址，WiFi MAC加1
def increment_mac(mac):
    mac_int = int(mac, 16)
    bt_mac_int = mac_int + 1
    bt_mac = '{:012x}'.format(bt_mac_int)
    return bt_mac.lower()

bt_mac = increment_mac(wifi_mac)

# 设置串口参数
try:
    ser = serial.Serial(port, 115200, timeout=1)
except serial.SerialException:
    print(f"无法打开串口 {port}")
    sys.exit(1)

time.sleep(2)  # 等待串口初始化

# 指令列表
commands = [
    'txevm -e 2',
    f'sn set_sn {sn}',
    f'mac {wifi_mac}',
    f'btmac {bt_mac}',
]

# 发送指令并接收设备响应
for cmd in commands:
    ser.write((cmd + '\r\n').encode())
    time.sleep(0.5)
    response = ser.readline().decode(errors='ignore').strip()
    print(f"发送指令: {cmd}")
    print(f"设备响应: {response}")

# 关闭串口
ser.close()