import socket
import threading
import select
import argparse

# 配置
INTERNAL_IP = '127.0.0.1'
INTERNAL_PORT = 12323

# 解析命令行参数
parser = argparse.ArgumentParser(description='Simple HTTP Proxy Server')
parser.add_argument('--external-ip', default='192.168.0.100', help='External network interface IP address')
args = parser.parse_args()
EXTERNAL_IP = args.external_ip

def handle_client(client_socket):
    try:
        # 接收客户端请求
        request = client_socket.recv(4096).decode()
        # 解析请求行
        lines = request.split('\n')
        if len(lines) > 0:
            method_line = lines[0]
            method_parts = method_line.split()
            if len(method_parts) >= 3:
                method = method_parts[0]
                url = method_parts[1]

                if method.upper() == 'CONNECT':
                    # 处理 HTTPS 请求
                    address = url.split(':')
                    remote_host = address[0]
                    remote_port = int(address[1]) if len(address) > 1 else 443

                    # 连接目标服务器
                    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote_socket.bind((EXTERNAL_IP, 0))
                    remote_socket.connect((remote_host, remote_port))

                    # 通知客户端连接已建立
                    client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')

                    # 转发数据
                    sockets = [client_socket, remote_socket]
                    while True:
                        r, _, _ = select.select(sockets, [], [])
                        if client_socket in r:
                            data = client_socket.recv(8192)
                            if not data:
                                break
                            remote_socket.sendall(data)
                        if remote_socket in r:
                            data = remote_socket.recv(8192)
                            if not data:
                                break
                            client_socket.sendall(data)
                    remote_socket.close()
                else:
                    # 处理 HTTP 请求
                    # 提取主机名
                    for line in lines:
                        if line.lower().startswith('host:'):
                            host_line = line
                            break
                    else:
                        client_socket.close()
                        return
                    host = host_line.split(':', 1)[1].strip()
                    if ':' in host:
                        remote_host, remote_port = host.split(':')
                        remote_port = int(remote_port)
                    else:
                        remote_host = host
                        remote_port = 80

                    # 建立与目标服务器的连接
                    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote_socket.bind((EXTERNAL_IP, 0))
                    remote_socket.connect((remote_host, remote_port))

                    # 转发请求
                    remote_socket.sendall(request.encode())

                    # 转发数据
                    sockets = [client_socket, remote_socket]
                    while True:
                        r, _, _ = select.select(sockets, [], [])
                        if client_socket in r:
                            data = client_socket.recv(8192)
                            if not data:
                                break
                            remote_socket.sendall(data)
                        if remote_socket in r:
                            data = remote_socket.recv(8192)
                            if not data:
                                break
                            client_socket.sendall(data)
                    remote_socket.close()
            else:
                client_socket.close()
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
    server.listen(100)
    print(f"[*] Listening on {INTERNAL_IP}:{INTERNAL_PORT}, external IP: {EXTERNAL_IP}")

    while True:
        client_socket, addr = server.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

        # 创建一个线程处理客户端请求
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_proxy()