import socket
import threading
import select
import argparse

# 配置
INTERNAL_IP = '127.0.0.1'
INTERNAL_PORT = 12323

# 解析命令行参数
parser = argparse.ArgumentParser(description='Simple SOCKS5 Proxy Server')
parser.add_argument('--external-ip', default='192.168.0.100', help='External network interface IP address')
args = parser.parse_args()
EXTERNAL_IP = args.external_ip

def handle_client(client_socket):
    try:
        # 握手
        client_socket.recv(262)
        client_socket.send(b"\x05\x00")

        # 请求
        data = client_socket.recv(4)
        if len(data) < 4:
            client_socket.close()
            return
        mode = data[1]
        addrtype = data[3]

        if addrtype == 1:  # IPv4
            addr = socket.inet_ntoa(client_socket.recv(4))
        elif addrtype == 3:  # 域名
            domain_length = client_socket.recv(1)[0]
            addr = client_socket.recv(domain_length).decode()
        else:
            client_socket.close()
            return
        port = int.from_bytes(client_socket.recv(2), 'big')

        if mode == 1:  # CONNECT 请求
            # 连接目标服务器
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.bind((EXTERNAL_IP, 0))
            remote_socket.connect((addr, port))

            # 响应客户端
            client_socket.send(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + (0).to_bytes(2, 'big'))

            # 转发数据
            while True:
                r, w, e = select.select([client_socket, remote_socket], [], [])
                if client_socket in r:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    remote_socket.sendall(data)
                if remote_socket in r:
                    data = remote_socket.recv(4096)
                    if not data:
                        break
                    client_socket.sendall(data)
        elif mode == 3:  # UDP ASSOCIATE 请求
            # 获取客户端地址
            client_addr = client_socket.getsockname()
            # 创建 UDP 套接字
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.bind((EXTERNAL_IP, 0))

            # 响应客户端，告知绑定的地址和端口
            bind_addr = udp_socket.getsockname()
            reply = b"\x05\x00\x00\x01" + socket.inet_aton(bind_addr[0]) + bind_addr[1].to_bytes(2, 'big')
            client_socket.send(reply)

            # 处理 UDP 转发（需要完善）
            # ...
        else:
            client_socket.close()
    except Exception as e:
        print(f"处理客户端时发生错误: {e}")
    finally:
        client_socket.close()

def start_proxy():
    # 创建一个监听内网网卡的socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((INTERNAL_IP, INTERNAL_PORT))
    server.listen(5)
    print(f"[*] Listening on {INTERNAL_IP}:{INTERNAL_PORT}, external IP: {EXTERNAL_IP}")

    while True:
        client_socket, addr = server.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

        # 创建一个线程处理客户端请求
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_proxy()