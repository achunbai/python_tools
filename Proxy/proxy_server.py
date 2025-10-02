import socket
import threading
import select
import argparse
import time

# 配置
INTERNAL_IP = '127.0.0.1'
INTERNAL_PORT = 12323

# 解析命令行参数
parser = argparse.ArgumentParser(description='Simple SOCKS5 Proxy Server')
parser.add_argument('--external-ip', default='192.168.0.100', help='External network interface IP address')
parser.add_argument('--port', type=int, default=12323, help='Internal listening port')
args = parser.parse_args()
EXTERNAL_IP = args.external_ip
INTERNAL_PORT = args.port

def handle_client(client_socket):
    remote_socket = None
    try:
        # 握手
        client_socket.recv(262)
        client_socket.send(b"\x05\x00")

        # 请求
        data = client_socket.recv(4)
        if len(data) < 4:
            return
        mode = data[1]
        addrtype = data[3]

        if addrtype == 1:  # IPv4
            addr = socket.inet_ntoa(client_socket.recv(4))
        elif addrtype == 3:  # 域名
            domain_length = client_socket.recv(1)[0]
            addr = client_socket.recv(domain_length).decode()
        else:
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
                try:
                    r, w, e = select.select([client_socket, remote_socket], [], [], 1.0)  # 添加超时
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
                except select.error:
                    break
                except socket.error:
                    break
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
    except Exception as e:
        print(f"处理客户端时发生错误: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass
        if remote_socket:
            try:
                remote_socket.close()
            except:
                pass

def start_proxy():
    # 创建一个监听内网网卡的socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # 设置端口重用选项
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # 尝试绑定端口，如果失败则尝试其他端口
    port_to_try = INTERNAL_PORT
    max_attempts = 10
    
    for attempt in range(max_attempts):
        try:
            server.bind((INTERNAL_IP, port_to_try))
            break
        except PermissionError as e:
            print(f"[!] Port {port_to_try} is not available: {e}")
            if attempt < max_attempts - 1:
                port_to_try += 1
                print(f"[*] Trying port {port_to_try}...")
                time.sleep(1)  # 等待一秒后重试
            else:
                print(f"[!] Failed to bind to any port after {max_attempts} attempts")
                server.close()
                return
        except Exception as e:
            print(f"[!] Unexpected error binding to port {port_to_try}: {e}")
            server.close()
            return
    
    server.listen(5)
    print(f"[*] Listening on {INTERNAL_IP}:{port_to_try}, external IP: {EXTERNAL_IP}")

    try:
        while True:
            client_socket, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

            # 创建一个线程处理客户端请求
            client_handler = threading.Thread(target=handle_client, args=(client_socket,))
            client_handler.daemon = True  # 设置为守护线程
            client_handler.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down proxy server...")
    except Exception as e:
        print(f"[!] Server error: {e}")
    finally:
        server.close()
        print("[*] Server closed")

if __name__ == "__main__":
    start_proxy()