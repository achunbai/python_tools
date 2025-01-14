# Simple HTTP/HTTPS Server

This is a simple HTTP/HTTPS server written in Python, supporting file uploads and basic authentication. The server can handle `multipart/form-data` POST requests and save uploaded files to a specified directory.

## Features

- **HTTP and HTTPS Support**: Runs simultaneously on both HTTP and HTTPS ports.
- **Basic Authentication**: Optional basic authentication enabled. The default username and password are `user`, but they can be customized.
- **File Upload**: Upload files via POST requests, which are saved to the `www/uploads` directory.
- **Logging**:
  - Request and response headers logging.
  - Processed request data logging.
  - Raw request data logging (including multipart boundaries).
- **Range Request Support**: Supports HTTP Range requests, allowing partial content transmission.

## Preparation

Prepare SSL certificates and key files in the `domain` directory, organized by domain name. For example, the certificate for `example.com` should be stored at `domain/example.com/example.com.pem` and the key at `domain/example.com/example.com.key`.

## Usage

Run the server:

```bash
python simple_web_server.py [options]
```

### Options

- `--domain`: Domain name, e.g., `example.com`. If not specified, `server.pem` and `server.key` will be used.
- `--http-port`: HTTP port, default is 80.
- `--https-port`: HTTPS port, default is 443.
- `--log-headers`: Enable logging of request/response headers.
- `--log-request-data`: Enable logging of processed request content (e.g., parsed POST data).
- `--log-raw-data`: Enable logging of raw request data (including multipart boundaries).
- `--enable-auth`: Enable basic authentication functionality.
- `--auth-username`: Authentication username (effective when authentication is enabled). Default is `user`.
- `--auth-password`: Authentication password (effective when authentication is enabled). Default is `user`.

### Examples

1. **Start the server with authentication enabled and all logs recorded**:

    ```bash
    python simple_web_server.py --enable-auth --auth-username admin --auth-password secret --log-headers --log-request-data --log-raw-data
    ```

2. **Upload a file**:

    Use `curl` to upload a file:

    ```bash
    curl -X POST http://your_server_ip/ -u admin:secret -F "file=@path/to/yourfile.txt"
    ```

    The uploaded file will be saved to the `www/uploads` directory.