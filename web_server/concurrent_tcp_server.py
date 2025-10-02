#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高并发TCP反射服务器
支持大量并发连接，专门用于TCP并发测试
"""

import socket
import threading
import time
import argparse
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
import logging

class ConcurrentTCPServer:
    def __init__(self, host="0.0.0.0", port=8888, max_connections=200):
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.server_socket = None
        self.running = False
        self.client_count = 0
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=max_connections)
        
        # 配置日志
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('tcp_server.log')
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def handle_client(self, client_socket, client_addr):
        """处理单个客户端连接"""
        client_id = f"{client_addr[0]}:{client_addr[1]}"
        
        with self.lock:
            self.client_count += 1
            current_count = self.client_count
            
        self.logger.info(f"[连接建立] 客户端 {client_id} 已连接 (当前连接数: {current_count})")
        
        try:
            while self.running:
                # 设置超时避免阻塞
                client_socket.settimeout(1.0)
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    # 记录接收到的数据
                    text = data.decode('utf-8', errors='ignore')
                    self.logger.debug(f"[接收] {client_id}: {text[:100]}...")
                    
                    # 反射数据（echo back）
                    client_socket.sendall(data)
                    self.logger.debug(f"[发送] {client_id}: 已反射 {len(data)} 字节")
                    
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    self.logger.info(f"[连接重置] 客户端 {client_id} 连接被重置")
                    break
                except Exception as e:
                    self.logger.error(f"[处理错误] {client_id}: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"[客户端处理异常] {client_id}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            
            with self.lock:
                self.client_count -= 1
                current_count = self.client_count
                
            self.logger.info(f"[连接断开] 客户端 {client_id} 已断开 (当前连接数: {current_count})")
    
    def start_server(self):
        """启动服务器"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 设置socket选项
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 在Windows上可能需要这个选项
        if hasattr(socket, 'SO_REUSEPORT'):
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_connections)
            self.running = True
            
            self.logger.info(f"[服务器启动] 监听 {self.host}:{self.port}")
            self.logger.info(f"[服务器配置] 最大连接数: {self.max_connections}")
            
            # 启动状态监控线程
            monitor_thread = threading.Thread(target=self.monitor_status, daemon=True)
            monitor_thread.start()
            
            while self.running:
                try:
                    self.server_socket.settimeout(1.0)
                    client_socket, client_addr = self.server_socket.accept()
                    
                    # 使用线程池处理客户端连接
                    self.executor.submit(self.handle_client, client_socket, client_addr)
                    
                except socket.timeout:
                    continue
                except OSError as e:
                    if self.running:
                        self.logger.error(f"[服务器错误] {e}")
                    break
                except Exception as e:
                    self.logger.error(f"[接受连接错误] {e}")
                    continue
                    
        except PermissionError:
            self.logger.error(f"[权限错误] 无法绑定端口 {self.port}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"[服务器启动错误] {e}")
            sys.exit(1)
        finally:
            self.stop_server()
    
    def monitor_status(self):
        """监控服务器状态"""
        while self.running:
            with self.lock:
                count = self.client_count
            self.logger.info(f"[状态监控] 当前活跃连接数: {count}")
            time.sleep(10)  # 每10秒打印一次状态
    
    def stop_server(self):
        """停止服务器"""
        self.logger.info("[服务器关闭] 正在关闭服务器...")
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # 关闭线程池
        self.executor.shutdown(wait=True)
        self.logger.info("[服务器关闭] 服务器已完全关闭")

def signal_handler(signum, frame):
    """信号处理器"""
    print(f"\n[信号] 接收到信号 {signum}，正在关闭服务器...")
    server.stop_server()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="高并发TCP反射服务器")
    parser.add_argument("-p", "--port", type=int, default=8888, 
                        help="监听端口 (默认: 8888)")
    parser.add_argument("-H", "--host", default="0.0.0.0", 
                        help="监听地址 (默认: 0.0.0.0)")
    parser.add_argument("-c", "--max-connections", type=int, default=200, 
                        help="最大并发连接数 (默认: 200)")
    parser.add_argument("-v", "--verbose", action="store_true", 
                        help="详细日志输出")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    global server
    server = ConcurrentTCPServer(
        host=args.host, 
        port=args.port, 
        max_connections=args.max_connections
    )
    
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\n[手动终止] 收到Ctrl+C，正在关闭服务器...")
        server.stop_server()

if __name__ == "__main__":
    main()
