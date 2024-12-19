import socket
import struct
import time

def ntp_server():
    # 创建UDP服务器套接字
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", 12345))
    print("NTP服务器正在运行，监听端口12345...")

    while True:
        # 接收NTP请求
        msg, addr = server.recvfrom(1024)
        print(f"收到来自 {addr} 的请求")

        # 解析客户端发送的原始时间戳
        if len(msg) < 48:
            print("收到的消息长度不足")
            continue

        # 提取原始时间戳
        originate_timestamp = struct.unpack('!12I', msg)[10:12]

        # 构建NTP响应
        # 参考NTP协议，构建48字节的响应数据包
        # LI = 0 (no warning), VN = 4 (version number), Mode = 4 (server)
        # Stratum = 1 (primary reference), Poll = 4, Precision = -6
        # Root Delay = 0, Root Dispersion = 0, Reference ID = 0x4C4F434C ("LOCL")
        # Reference Timestamp, Originate Timestamp, Receive Timestamp, Transmit Timestamp
        transmit_timestamp = time.time() + 2208988800  # 转换为NTP时间戳
        response = struct.pack('!B B B b 11I', 
                               0x1c,  # LI, VN, Mode
                               1,     # Stratum
                               4,     # Poll
                               -6,    # Precision
                               0,     # Root Delay
                               0,     # Root Dispersion
                               0x4C4F434C,  # Reference ID ("LOCL")
                               0, 0,  # Reference Timestamp
                               originate_timestamp[0], originate_timestamp[1],  # Originate Timestamp
                               int(transmit_timestamp),  # Receive Timestamp (seconds)
                               int((transmit_timestamp - int(transmit_timestamp)) * 2**32),  # Receive Timestamp (fraction)
                               int(transmit_timestamp),  # Transmit Timestamp (seconds)
                               int((transmit_timestamp - int(transmit_timestamp)) * 2**32))  # Transmit Timestamp (fraction)

        # 发送NTP响应
        server.sendto(response, addr)
        print(f"发送响应到 {addr}")

if __name__ == "__main__":
    ntp_server()