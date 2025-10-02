# Simple Web Server

一个功能丰富的 Python HTTP/HTTPS 文件服务器，支持文件上传、范围请求、基础认证和详细的调试日志功能。

## 🌟 特性

- **双协议支持**：同时运行 HTTP 和 HTTPS 服务器
- **SSL/TLS 加密**：支持自定义域名证书
- **文件上传**：通过 POST 请求上传文件到服务器
- **范围请求**：支持 HTTP Range 请求
- **基础认证**：可选的用户名/密码认证保护
- **多线程处理**：并发处理多个客户端连接
- **详细日志**：多级别的调试和监控功能

## 📋 系统要求

- Python 3.6+
- 无需额外依赖包（仅使用标准库）

## 🚀 快速开始

### 基本使用

```bash
# 基础 HTTP/HTTPS 服务器（需要管理员权限）
python simple_web_server.py

# 使用非特权端口
python simple_web_server.py --http-port 8080 --https-port 8443

# 启用基础认证
python simple_web_server.py --enable-auth --auth-username admin --auth-password secret
```

### SSL 证书设置

服务器已提供默认的自签名证书，位于 `domain/server/` 目录。

如需使用自定义域名证书，请将证书文件放置在相应目录：

```
domain/
├── server/          # 默认证书（已提供）
│   ├── server.pem   # 证书文件
│   └── server.key   # 私钥文件
├── example.com/     # 自定义域名证书
│   ├── example.com.pem
│   └── example.com.key
```

使用自定义域名证书：
```bash
python simple_web_server.py --domain example.com
```

**申请免费证书：**
可使用 Let's Encrypt 的 DNS 验证方式申请免费 SSL 证书。

## 📁 目录结构

```
project/
├── simple_web_server.py    # 主程序
├── index.html             # 默认首页（可选）
├── www/                   # Web 根目录
│   ├── index.html         # 自动复制的首页
│   ├── uploads/           # 文件上传目录
│   └── ...               # 其他静态文件
├── domain/               # SSL 证书目录
│   ├── server/           # 默认证书
│   └── yourdomain.com/   # 自定义域名证书
└── log.txt              # 日志文件（启用文件日志时）
```

## 🔧 命令行参数

### 服务器配置
- `--domain DOMAIN`：指定 SSL 证书域名（默认：server）
- `--http-port PORT`：HTTP 端口（默认：80）
- `--https-port PORT`：HTTPS 端口（默认：443）

### 认证设置
- `--enable-auth`：启用基础认证
- `--auth-username USER`：认证用户名（默认：user）
- `--auth-password PASS`：认证密码（默认：user）

### 日志调试
- `--log-headers`：记录请求/响应头信息
- `--log-request-data`：记录处理后的请求数据
- `--log-raw-data`：记录原始请求数据（包括多部分边界）
- `--enable-file-log`：启用文件日志
- `--log-file PATH`：日志文件路径（默认：log.txt）
- `--log-level LEVEL`：日志级别（DEBUG/INFO/WARNING/ERROR，默认：INFO）

## 💡 使用示例

### 测试开发环境
```bash
# 启用所有调试功能
python simple_web_server.py --http-port 8080 --https-port 8443 \
  --log-headers --log-request-data --enable-file-log --log-level DEBUG

# 安全测试
python simple_web_server.py --enable-auth --auth-username admin --auth-password complex_password \
  --log-headers --enable-file-log
```

### 文件共享测试
```bash
# 简单文件共享（局域网测试）
python simple_web_server.py --http-port 8000 --https-port 8443
```

## 📤 文件管理与上传

### 文件上传方式

服务器支持多种方式上传文件到 `www/uploads/` 目录：

**1. HTML 表单上传**
```html
<!DOCTYPE html>
<html>
<body>
    <h2>文件上传</h2>
    <form action="/" method="post" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <input type="submit" value="上传">
    </form>
</body>
</html>
```

**2. 命令行工具上传**
```bash
# 使用 curl
curl -X POST http://localhost:8080/ -F "file=@yourfile.bin"

# 使用 wget
wget --post-file=yourfile.bin http://localhost:8080/

# 使用 PowerShell (Windows)
Invoke-RestMethod -Uri "http://localhost:8080/" -Method Post -InFile "yourfile.bin"
```

**3. 编程接口上传**
- AT指令上传
- Python requests库
- 其他HTTP客户端工具

**4. 直接文件放置**
除了上传，也可以直接将文件复制到相应目录：
- 将文件复制到 `www/` 目录作为静态文件访问
- 将固件文件复制到 `www/` 目录进行OTA升级测试

### OTA 升级固件测试

**固件放置方式：**
```bash
# 直接复制固件到 www 目录
cp my_firmware.bin www/
cp my_firmware.signed.bin www/

# 或者通过上传方式
curl -X POST http://localhost:8080/ -F "file=@my_firmware.bin"
```

**固件访问：**
```bash
# 设备可通过以下URL下载固件
http://your_server:8080/my_firmware.bin
https://your_server:8443/my_firmware.signed.bin
```

**测试示例：**
- 将 `my_firmware.bin` 放入 `www/` 目录
- 设备访问 `http://server_ip:8080/my_firmware.bin`
- 支持断点续传和范围请求

## 🔍 范围请求支持

服务器支持 HTTP Range 请求。

客户端示例：
```bash
# 下载文件的前1024字节
curl -H "Range: bytes=0-1023" http://localhost:8080/largefile.zip

# 下载文件的后半部分
curl -H "Range: bytes=1024-" http://localhost:8080/largefile.zip
```

## 🐛 调试功能

### 日志级别说明
- **DEBUG**：详细的调试信息，包括连接状态
- **INFO**：常规操作信息
- **WARNING**：潜在问题警告（如SSL握手失败）
- **ERROR**：错误和异常情况

### 调试选项详解
```bash
# 查看所有HTTP头信息
python simple_web_server.py --log-headers

# 查看POST数据处理过程
python simple_web_server.py --log-request-data

# 查看完整的原始请求数据
python simple_web_server.py --log-raw-data

# 组合使用，保存到文件
python simple_web_server.py --log-headers --log-request-data --log-raw-data \
  --enable-file-log --log-file debug.log --log-level DEBUG
```

## 🚨 常见问题

### SSL 证书问题
**问题**：`SSL handshake failed` 警告
**解决**：这是正常现象，通常是浏览器不信任自签名证书导致的。可以：
1. 在浏览器中手动信任证书
2. 使用有效的CA签发证书
3. 忽略此警告（不影响HTTP功能）

### 权限问题
**问题**：`Permission denied` 绑定80/443端口
**解决**：
- Windows：以管理员身份运行
- Linux/macOS：使用 `sudo` 或改用非特权端口（>1024）

### 文件上传失败
**问题**：上传的文件没有保存
**解决**：
1. 确保 `www/uploads/` 目录存在且可写
2. 检查磁盘空间
3. 启用 `--log-request-data` 查看详细信息

### OTA升级测试问题
**问题**：设备无法下载固件
**解决**：
1. 确认固件文件已正确放置在 `www/` 目录
2. 检查文件权限和服务器端口访问
3. 使用浏览器先测试文件是否可正常访问
4. 启用 `--log-headers` 查看请求详情