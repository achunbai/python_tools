import socket
import struct
import time

# 定义NTP服务器列表
# ntp_servers = ["ntp1.aliyun.com", "cn.pool.ntp.org", "time.asia.apple.com"]
ntp_servers = ["10.55.25.127", "ntp1.aliyun.com", "cn.pool.ntp.org", "time.asia.apple.com", "ntp.ntsc.ac.cn", "0.cn.pool.ntp.org", "cn.ntp.org.cn", "time.cloudflare.com"]

# 指定网卡的IP地址
interface_ip = "0.0.0.0"  # 替换为你的网卡IP地址

def get_ntp_time(ntp_server):
    # 创建UDP套接字
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(5)
    
    # 绑定到指定的网卡
    client.bind((interface_ip, 0))
    
    # 构建NTP请求数据包
    msg = b'\x1b' + 47 * b'\0'
    
    try:
        # 解析NTP服务器的IP地址
        server_ip = socket.gethostbyname(ntp_server)
        
        # 发送NTP请求
        client.sendto(msg, (server_ip, 123))
        # client.sendto(msg, (server_ip, 12345))
        
        # 接收NTP响应
        msg, _ = client.recvfrom(1024)
    except socket.timeout:
        print(f"无法从NTP服务器 {ntp_server} 获取响应")
        return None, None
    finally:
        client.close()
    
    # 解析NTP响应
    unpacked = struct.unpack('!12I', msg[0:48])
    transmit_timestamp = unpacked[10] + float(unpacked[11]) / 2**32
    ntp_time = transmit_timestamp - 2208988800  # 转换为UNIX时间戳
    
    return ntp_time, server_ip

def main():
    for ntp_server in ntp_servers:
        ntp_time, server_ip = get_ntp_time(ntp_server)
        if ntp_time:
            print(f"从NTP服务器 {ntp_server} ({server_ip}) 获取的时间: {time.ctime(ntp_time)}")
        time.sleep(1)

if __name__ == "__main__":
    while True:
        main()