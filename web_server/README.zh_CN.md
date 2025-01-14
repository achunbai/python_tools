# 简易HTTP/HTTPS服务器

这是一个使用Python编写的简单HTTP/HTTPS服务器，支持文件上传和基本认证功能。服务器可以处理`multipart/form-data`类型的POST请求，并将上传的文件保存到指定目录。

## 功能

- **HTTP和HTTPS支持**：同时支持HTTP和HTTPS，默认HTTP端口为80，HTTPS为443，可设置。
- **基本认证**：可选启用基本认证，默认用户名和密码均为`user`，可自定义。
- **文件上传**：通过POST请求上传文件，文件将保存到`www/uploads`目录。
- **日志记录**：
  - 请求和响应头日志。
  - 处理后的请求数据日志。
  - 原始请求数据日志（包含multipart边界等）。
- **Range请求支持**：支持HTTP Range请求，允许部分内容传输。

## 准备工作

在`domain`目录下准备SSL证书和密钥文件，按照域名来存储，比如`example.com`的证书将保存在`domain/example.com/example.com.pem`，密钥将保存在`domain/example.com/example.com.key`。

## 使用

运行服务器：

```bash
python simple_web_server.py [选项]
```

### 选项

- `--domain`: 域名，例如 `example.com`。如果未指定，将使用 `server.pem` 和 `server.key`。
- `--http-port`: HTTP端口，默认是80。
- `--https-port`: HTTPS端口，默认是443。
- `--log-headers`: 是否输出请求/响应头。
- `--log-request-data`: 是否输出处理后的请求内容（如解析后的POST数据）。
- `--log-raw-data`: 是否输出原始请求数据（包含multipart边界等）。
- `--enable-auth`: 是否启用基本认证功能。
- `--auth-username`: 认证用户名（启用认证时有效）。默认值为`user`。
- `--auth-password`: 认证密码（启用认证时有效）。默认值为`user`。

### 示例

1. **启动服务器，启用认证并记录所有日志**：

    ```bash
    python simple_web_server.py --enable-auth --auth-username admin --auth-password secret --log-headers --log-request-data --log-raw-data
    ```

2. **上传文件**：

    使用`curl`上传文件：

    ```bash
    curl -X POST http://your_server_ip/ -u admin:secret -F "file=@path/to/yourfile.txt"
    ```

    上传的文件将被保存到`www/uploads`目录。