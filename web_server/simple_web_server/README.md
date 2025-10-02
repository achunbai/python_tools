# Simple Web Server

A feature-rich Python HTTP/HTTPS file server with file upload support, range requests, basic authentication, and comprehensive debugging logging capabilities.

## 🌟 Features

- **Dual Protocol Support**: Simultaneous HTTP and HTTPS servers
- **SSL/TLS Encryption**: Support for custom domain certificates
- **File Upload**: Upload files to server via POST requests
- **Range Requests**: HTTP Range request support
- **Basic Authentication**: Optional username/password authentication protection
- **Multi-threading**: Concurrent handling of multiple client connections
- **Detailed Logging**: Multi-level debugging and monitoring capabilities

## 📋 System Requirements

- Python 3.6+
- No additional dependencies required (uses standard library only)

## 🚀 Quick Start

### Basic Usage

```bash
# Basic HTTP/HTTPS server (requires administrator privileges)
python simple_web_server.py

# Use non-privileged ports
python simple_web_server.py --http-port 8080 --https-port 8443

# Enable basic authentication
python simple_web_server.py --enable-auth --auth-username admin --auth-password secret
```

### SSL Certificate Setup

The server provides default self-signed certificates located in the `domain/server/` directory.

For custom domain certificates, place certificate files in the appropriate directory:

```
domain/
├── server/          # Default certificate (provided)
│   ├── server.pem   # Certificate file
│   └── server.key   # Private key file
├── example.com/     # Custom domain certificate
│   ├── example.com.pem
│   └── example.com.key
```

Use custom domain certificate:
```bash
python simple_web_server.py --domain example.com
```

**Free Certificate:**
You can use Let's Encrypt with DNS validation to obtain free SSL certificates.

## 📁 Directory Structure

```
project/
├── simple_web_server.py    # Main program
├── index.html             # Default homepage (optional)
├── www/                   # Web root directory
│   ├── index.html         # Automatically copied homepage
│   ├── uploads/           # File upload directory
│   └── ...               # Other static files
├── domain/               # SSL certificate directory
│   ├── server/           # Default certificate
│   └── yourdomain.com/   # Custom domain certificate
└── log.txt              # Log file (when file logging is enabled)
```

## 🔧 Command Line Arguments

### Server Configuration
- `--domain DOMAIN`: Specify SSL certificate domain (default: server)
- `--http-port PORT`: HTTP port (default: 80)
- `--https-port PORT`: HTTPS port (default: 443)

### Authentication Settings
- `--enable-auth`: Enable basic authentication
- `--auth-username USER`: Authentication username (default: user)
- `--auth-password PASS`: Authentication password (default: user)

### Logging & Debugging
- `--log-headers`: Log request/response header information
- `--log-request-data`: Log processed request data
- `--log-raw-data`: Log raw request data (including multipart boundaries)
- `--enable-file-log`: Enable file logging
- `--log-file PATH`: Log file path (default: log.txt)
- `--log-level LEVEL`: Log level (DEBUG/INFO/WARNING/ERROR, default: INFO)

## 💡 Usage Examples

### Testing & Development Environment
```bash
# Enable all debugging features
python simple_web_server.py --http-port 8080 --https-port 8443 \
  --log-headers --log-request-data --enable-file-log --log-level DEBUG

# Security testing
python simple_web_server.py --enable-auth --auth-username admin --auth-password complex_password \
  --log-headers --enable-file-log
```

### File Sharing Test
```bash
# Simple file sharing (LAN testing)
python simple_web_server.py --http-port 8000 --https-port 8443
```

## 📤 File Management & Upload

### File Upload Methods

The server supports multiple ways to upload files to the `www/uploads/` directory:

**1. HTML Form Upload**
```html
<!DOCTYPE html>
<html>
<body>
    <h2>File Upload</h2>
    <form action="/" method="post" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <input type="submit" value="Upload">
    </form>
</body>
</html>
```

**2. Command Line Tools**
```bash
# Using curl
curl -X POST http://localhost:8080/ -F "file=@yourfile.bin"

# Using wget
wget --post-file=yourfile.bin http://localhost:8080/

# Using PowerShell (Windows)
Invoke-RestMethod -Uri "http://localhost:8080/" -Method Post -InFile "yourfile.bin"
```

**3. Programming Interfaces**
- AT commands
- Python requests library
- Other HTTP client tools

**4. Direct File Placement**
Besides uploading, you can also directly copy files to the appropriate directories:
- Copy files to `www/` directory for static file access
- Copy firmware files to `www/` directory for OTA upgrade testing

### OTA Firmware Upgrade Testing

**Firmware Placement:**
```bash
# Directly copy firmware to www directory
cp my_firmware.bin www/
cp my_firmware.signed.bin www/

# Or upload via HTTP
curl -X POST http://localhost:8080/ -F "file=@my_firmware.bin"
```

**Firmware Access:**
```bash
# Devices can download firmware via these URLs
http://your_server:8080/my_firmware.bin
https://your_server:8443/my_firmware.signed.bin
```

**Testing Example:**
- Place `my_firmware.bin` in `www/` directory
- Device accesses `http://server_ip:8080/my_firmware.bin`
- Supports resume downloads and range requests

## 🔍 Range Request Support

The server supports HTTP Range requests.

Client examples:
```bash
# Download first 1024 bytes of a file
curl -H "Range: bytes=0-1023" http://localhost:8080/largefile.zip

# Download the second half of a file
curl -H "Range: bytes=1024-" http://localhost:8080/largefile.zip
```

## 🐛 Debugging Features

### Log Level Descriptions
- **DEBUG**: Detailed debugging information, including connection status
- **INFO**: Regular operation information
- **WARNING**: Potential issue warnings (e.g., SSL handshake failures)
- **ERROR**: Error and exception conditions

### Debugging Options Explained
```bash
# View all HTTP header information
python simple_web_server.py --log-headers

# View POST data processing
python simple_web_server.py --log-request-data

# View complete raw request data
python simple_web_server.py --log-raw-data

# Combined usage, save to file
python simple_web_server.py --log-headers --log-request-data --log-raw-data \
  --enable-file-log --log-file debug.log --log-level DEBUG
```

## 🚨 Common Issues

### SSL Certificate Issues
**Problem**: `SSL handshake failed` warnings
**Solution**: This is normal behavior, usually caused by browsers not trusting self-signed certificates. You can:
1. Manually trust the certificate in your browser
2. Use a valid CA-issued certificate
3. Ignore this warning (doesn't affect HTTP functionality)

### Permission Issues
**Problem**: `Permission denied` when binding to ports 80/443
**Solution**:
- Windows: Run as Administrator
- Linux/macOS: Use `sudo` or switch to non-privileged ports (>1024)

### File Upload Failures
**Problem**: Uploaded files are not being saved
**Solution**:
1. Ensure `www/uploads/` directory exists and is writable
2. Check available disk space
3. Enable `--log-request-data` to view detailed information

### OTA Upgrade Testing Issues
**Problem**: Device cannot download firmware
**Solution**:
1. Confirm firmware file is correctly placed in `www/` directory
2. Check file permissions and server port access
3. Test file access with a browser first
4. Enable `--log-headers` to view request details
python -m pip install legacy-cgi
```

[Optional] Prepare SSL certificate and key files in the `domain` directory, organized by domain name. For example, the certificate for `example.com` should be saved as `domain/example.com/example.com.pem`, and the key should be saved as `domain/example.com/example.com.key`.

[Optional] Replace `index.html` with your preferred page.

## Usage

Run the server:

```bash
python simple_web_server.py [options]
```

### Options

You can omit any options you don't need from the following:

- `--domain`: Domain name, e.g., `example.com`. If not specified, `server.pem` and `server.key` will be used.
- `--http-port`: HTTP port, default is 80.
- `--https-port`: HTTPS port, default is 443.
- `--log-headers`: Whether to output request/response headers.
- `--log-request-data`: Whether to output processed request content (such as parsed POST data).
- `--log-raw-data`: Whether to output raw request data (including multipart boundaries, etc.).
- `--enable-auth`: Whether to enable basic authentication.
- `--auth-username`: Authentication username (valid when authentication is enabled). Default value is `user`.
- `--auth-password`: Authentication password (valid when authentication is enabled). Default value is `user`.

### Examples

1. **Start server with authentication enabled and all logging**:

    ```bash
    python simple_web_server.py --enable-auth --auth-username admin --auth-password secret --log-headers --log-request-data --log-raw-data
    ```

2. **Start server with default settings and set example.com as domain (requires SSL certificate to be obtained in advance and placed in the domain folder, can use Let's Encrypt)**

    ```bash
    python simple_web_server.py --domain example.com
    ```

2. **Start server with default settings, no additional configuration**

    ```bash
    python simple_web_server.py
    ```

3. **Upload files**:

    Use `curl` to upload files (you can upload directly with AT commands, the following is just a curl demonstration):

    ```bash
    curl -X POST http://your_server_ip/ -u admin:secret -F "file=@path/to/yourfile.txt"
    ```

    Uploaded files will be saved to the `www/uploads` directory.