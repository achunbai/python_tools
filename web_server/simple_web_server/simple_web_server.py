#!/usr/bin/env python3
"""
Simple HTTP/HTTPS Web Server with File Upload and Range Requests Support

Features:
- HTTP and HTTPS support with custom certificates
- Basic authentication (optional)
- File upload functionality
- Range requests for video streaming
- Comprehensive logging options
- Multi-threading support
- Graceful SSL error handling

"""

import http.server
import socketserver
import ssl
import os
import threading
import shutil
from functools import partial
import base64
import re
import argparse
import logging
import sys

# Configuration
WWW_DIR = os.path.join(os.getcwd(), 'www')
DOMAIN_DIR = os.path.join(os.getcwd(), 'domain')
UPLOAD_DIR = os.path.join(WWW_DIR, 'uploads')

# Ensure directories exist
for directory in [WWW_DIR, UPLOAD_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Copy default index.html if it doesn't exist
index_src = os.path.join(os.path.dirname(__file__), 'index.html')
index_dst = os.path.join(WWW_DIR, 'index.html')
if os.path.exists(index_src) and not os.path.exists(index_dst):
    shutil.copy(index_src, index_dst)

# Regex for parsing byte range requests
BYTE_RANGE_RE = re.compile(r'bytes=(\d+)-(\d+)?$')


def parse_byte_range(byte_range):
    """Parse byte range header and return start/end positions."""
    if byte_range.strip() == '':
        return None, None

    match = BYTE_RANGE_RE.match(byte_range)
    if not match:
        raise ValueError(f'Invalid byte range {byte_range}')

    first, last = [x and int(x) for x in match.groups()]
    if last and last < first:
        raise ValueError(f'Invalid byte range {byte_range}')
    return first, last


def copy_byte_range(infile, outfile, start=None, stop=None, bufsize=16*1024):
    """Copy a specific byte range from input file to output file."""
    if start is not None:
        infile.seek(start)
    
    while True:
        to_read = min(bufsize, stop + 1 - infile.tell() if stop is not None else bufsize)
        buf = infile.read(to_read)
        if not buf:
            break
        outfile.write(buf)


class ThreadingTCPServerWithErrorHandling(socketserver.ThreadingTCPServer):
    """Custom threading TCP server that handles SSL errors gracefully."""
    
    def handle_error(self, request, client_address):
        """Override to handle SSL and connection errors more gracefully."""
        exc_type, exc_value, exc_traceback = sys.exc_info()
        
        # Handle SSL-related errors and connection aborts quietly
        if isinstance(exc_value, (ConnectionAbortedError, ssl.SSLError)):
            logging.debug(f"Connection from {client_address} failed: {exc_value}")
            return
        
        # Handle other connection errors quietly
        if isinstance(exc_value, (ConnectionResetError, BrokenPipeError, OSError)):
            logging.debug(f"Connection from {client_address} interrupted: {exc_value}")
            return
        
        # For other exceptions, log them normally
        logging.error(f"Exception occurred during processing of request from {client_address}")
        logging.error(f"Exception: {exc_type.__name__}: {exc_value}")


class RangeRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Enhanced HTTP request handler with the following features:
    - Range request support for video streaming
    - Basic authentication
    - File upload via POST
    - Comprehensive logging options
    - Graceful SSL error handling
    """
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, log_headers=False, log_request_data=False, log_raw_data=False,
                 enable_auth=False, auth_username='user', auth_password='user',
                 enable_file_logging=False, log_file_path='log.txt', directory=None, **kwargs):
        self.log_headers = log_headers
        self.log_request_data = log_request_data
        self.log_raw_data = log_raw_data
        self.enable_auth = enable_auth
        self.auth_username = auth_username
        self.auth_password = auth_password
        self.enable_file_logging = enable_file_logging
        self.log_file_path = log_file_path
        self.response_headers = {}
        self.raw_request = ""
        super().__init__(*args, directory=directory, **kwargs)

    def setup(self):
        """Setup SSL connection if configured."""
        super().setup()
        ctx = getattr(self.server, 'ssl_context', None)
        if ctx:
            try:
                self.request = ctx.wrap_socket(self.request, server_side=True)
                self.rfile = self.request.makefile('rb', buffering=0)
                self.wfile = self.request.makefile('wb', buffering=0)
            except ssl.SSLError as e:
                logging.warning(f"SSL handshake failed from {getattr(self, 'client_address', 'unknown')}: {e}")
                try:
                    self.request.close()
                except:
                    pass
                raise ConnectionAbortedError("SSL handshake failed")
            except Exception as e:
                logging.error(f"Error during per-connection SSL wrap: {e}")
                try:
                    self.request.close()
                except:
                    pass
                raise ConnectionAbortedError("SSL setup failed")

    def log_message(self, format, *args):
        """Override to use logging instead of print."""
        message = "%s - - [%s] %s" % (
            self.client_address[0],
            self.log_date_time_string(),
            format % args
        )
        logging.info(message)

    def send_header(self, keyword, value):
        """Track response headers for debugging."""
        super().send_header(keyword, value)
        self.response_headers[keyword] = value

    def end_headers(self):
        """Log response headers if debugging is enabled."""
        super().end_headers()
        if self.log_headers:
            logging.info("Response Headers:")
            for header, value in self.response_headers.items():
                logging.info(f"  {header}: {value}")
        self.response_headers.clear()

    def authenticate(self):
        """Handle basic authentication."""
        if not self.enable_auth:
            return True

        auth_header = self.headers.get('Authorization')
        if auth_header is None:
            self._request_authentication()
            return False

        try:
            auth_type, encoded_credentials = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                self._request_authentication()
                return False

            decoded_credentials = base64.b64decode(encoded_credentials.strip()).decode('utf-8')
            username, password = decoded_credentials.split(':', 1)

            if username == self.auth_username and password == self.auth_password:
                return True
            else:
                self._request_authentication()
                return False
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            if self.log_raw_data:
                logging.error("Original Request:")
                logging.error(self.raw_request)
            self._request_authentication()
            return False

    def _request_authentication(self):
        """Send 401 authentication required response."""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Protected Area"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Authentication required.')

    def _log_request_headers(self):
        """Log request headers if debugging is enabled."""
        if self.log_headers:
            logging.info("Request Headers:")
            for header, value in self.headers.items():
                logging.info(f"  {header}: {value}")

    def _build_raw_request(self, include_body=False):
        """Build raw request string for debugging."""
        self.raw_request = f"{self.requestline}\r\n"
        for header, value in self.headers.items():
            self.raw_request += f"{header}: {value}\r\n"
        self.raw_request += "\r\n"
        
        if include_body:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                try:
                    post_data = self.rfile.read(content_length)
                    try:
                        self.raw_request += post_data.decode('utf-8', errors='replace')
                    except:
                        self.raw_request += "<binary data>"
                    return post_data
                except:
                    self.raw_request += "<failed to read body>"
        return None

    def send_head(self):
        """Handle HEAD and GET requests with range support."""
        self._log_request_headers()
        self._build_raw_request()

        if self.enable_auth and not self.authenticate():
            return None

        # Handle range requests
        if 'Range' not in self.headers:
            self.range = None
            return super().send_head()

        try:
            self.range = parse_byte_range(self.headers['Range'])
        except ValueError:
            self.send_error(400, 'Invalid byte range')
            return None

        first, last = self.range
        path = self.translate_path(self.path)
        
        try:
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, 'File not found')
            return None

        fs = os.fstat(f.fileno())
        file_len = fs.st_size
        
        if first >= file_len:
            self.send_error(416, 'Requested Range Not Satisfiable')
            f.close()
            return None

        self.send_response(206)
        ctype = self.guess_type(path)
        self.send_header('Content-type', ctype)
        self.send_header('Accept-Ranges', 'bytes')

        if last is None or last >= file_len:
            last = file_len - 1
        response_length = last - first + 1

        self.send_header('Content-Range', f'bytes {first}-{last}/{file_len}')
        self.send_header('Content-Length', str(response_length))
        self.send_header('Last-Modified', self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f

    def copyfile(self, source, outputfile):
        """Copy file with range support."""
        if not self.range:
            return super().copyfile(source, outputfile)

        start, stop = self.range
        copy_byte_range(source, outputfile, start, stop)

    def do_POST(self):
        """Handle POST requests for file upload."""
        self._log_request_headers()
        post_data = self._build_raw_request(include_body=True)

        if self.enable_auth and not self.authenticate():
            return

        if self.log_raw_data:
            logging.info("Raw Request:")
            logging.info(self.raw_request)

        content_type = self.headers.get('Content-Type', '')
        
        if 'multipart/form-data' in content_type:
            self._handle_file_upload(post_data, content_type)
        else:
            if self.log_request_data:
                try:
                    decoded_post = post_data.decode('utf-8', errors='replace') if post_data else ""
                    logging.info("POST Data:")
                    logging.info(decoded_post)
                except:
                    logging.info("POST Data: <binary data>")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"POST received successfully.")

    def _handle_file_upload(self, post_data, content_type):
        """Handle multipart file upload."""
        # Extract boundary
        boundary = None
        for part in content_type.split(';'):
            part = part.strip()
            if part.startswith('boundary='):
                boundary = part.split('=', 1)[1]
                break
        
        if not boundary:
            self.send_error(400, "Bad Request: Missing boundary in multipart/form-data")
            return
        
        # Remove optional quotes
        if boundary.startswith('"') and boundary.endswith('"'):
            boundary = boundary[1:-1]

        try:
            fields = self._parse_multipart(post_data, boundary)
        except Exception as e:
            logging.error(f"Multipart parse error: {e}")
            self.send_error(400, "Bad Request: Unable to parse multipart data")
            return

        if 'file' in fields:
            file_field = fields['file']
            if file_field.get('filename'):
                filename = os.path.basename(file_field['filename'])
                file_path = os.path.join(UPLOAD_DIR, filename)
                try:
                    with open(file_path, 'wb') as output_file:
                        output_file.write(file_field.get('content', b''))
                    if self.enable_file_logging:
                        logging.info(f"File uploaded: {file_path}")
                except Exception as e:
                    logging.error(f"Error saving file: {e}")
                    self.send_error(500, "Internal Server Error: Unable to save file")
                    return
            else:
                self.send_error(400, "Bad Request: No filename provided")
                return
        else:
            self.send_error(400, "Bad Request: No file field in form")
            return

    def _parse_multipart(self, data: bytes, boundary_str: str):
        """Parse multipart form data."""
        b_boundary = ("--" + boundary_str).encode('utf-8')
        parts = data.split(b_boundary)
        fields = {}
        
        for part in parts:
            if not part or part == b'--' or part == b'--\r\n':
                continue
            
            # Strip leading CRLF
            if part.startswith(b'\r\n'):
                part = part[2:]
            
            # Strip trailing CRLF or --
            if part.endswith(b'\r\n'):
                part = part[:-2]
            if part.endswith(b'--'):
                part = part[:-2]

            header_section, sep, body = part.partition(b'\r\n\r\n')
            if sep == b'':
                continue
            
            try:
                header_text = header_section.decode('utf-8', errors='replace')
            except Exception:
                header_text = ''
            
            headers = {}
            for line in header_text.split('\r\n'):
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip().lower()] = v.strip()

            disp = headers.get('content-disposition', '')
            m_name = re.search(r'name="([^\"]+)"', disp)
            name = m_name.group(1) if m_name else None
            m_filename = re.search(r'filename="([^\"]+)"', disp)
            filename = m_filename.group(1) if m_filename else None

            fields[name] = {
                'filename': filename,
                'content': body
            }
        
        return fields


def create_ssl_context(domain):
    """Create SSL context from certificate files."""
    if not domain:
        domain = "server"
    
    cert_path = os.path.join(DOMAIN_DIR, domain, f"{domain}.pem")
    key_path = os.path.join(DOMAIN_DIR, domain, f"{domain}.key")
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        logging.error(f"Cannot find certificate or key for domain '{domain}'.")
        logging.error(f"Expected files: {cert_path}, {key_path}")
        return None
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        logging.info(f"SSL context created successfully for domain '{domain}'")
        return context
    except Exception as e:
        logging.error(f"Failed to load SSL certificates: {e}")
        return None


def run_https_server(domain, port, log_headers, log_request_data, log_raw_data,
                    enable_auth, auth_username, auth_password,
                    enable_file_logging, log_file_path):
    """Run HTTPS server."""
    handler = partial(
        RangeRequestHandler,
        log_headers=log_headers,
        log_request_data=log_request_data,
        log_raw_data=log_raw_data,
        enable_auth=enable_auth,
        auth_username=auth_username,
        auth_password=auth_password,
        enable_file_logging=enable_file_logging,
        log_file_path=log_file_path,
        directory=WWW_DIR
    )
    
    httpd = ThreadingTCPServerWithErrorHandling(("", port), handler)
    httpd.allow_reuse_address = True
    httpd.daemon_threads = True
    
    context = create_ssl_context(domain)
    if context:
        httpd.ssl_context = context
        logging.info(f"[HTTPS] Serving on port {port} (Domain='{domain if domain else 'server'}')...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.info("HTTPS server stopped by user")
    else:
        logging.error("Unable to create SSL context. HTTPS server not started.")


def run_http_server(port, log_headers, log_request_data, log_raw_data,
                   enable_auth, auth_username, auth_password,
                   enable_file_logging, log_file_path):
    """Run HTTP server."""
    handler = partial(
        RangeRequestHandler,
        log_headers=log_headers,
        log_request_data=log_request_data,
        log_raw_data=log_raw_data,
        enable_auth=enable_auth,
        auth_username=auth_username,
        auth_password=auth_password,
        enable_file_logging=enable_file_logging,
        log_file_path=log_file_path,
        directory=WWW_DIR
    )
    
    httpd = ThreadingTCPServerWithErrorHandling(("", port), handler)
    httpd.allow_reuse_address = True
    httpd.daemon_threads = True
    
    logging.info(f"[HTTP] Serving on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("HTTP server stopped by user")


def setup_logging(enable_file_log, log_file, log_level="INFO"):
    """Setup logging configuration."""
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper()))

    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler
    if enable_file_log:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_path = os.path.join(script_dir, log_file)
        file_handler = logging.FileHandler(log_path, mode='w', encoding='utf-8')
        file_handler.setLevel(getattr(logging, log_level.upper()))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logging.info(f"File logging enabled: {log_path}")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Simple HTTP/HTTPS server with file upload and range requests support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python simple_web_server.py                           # Basic HTTP/HTTPS server
  python simple_web_server.py --http-port 8080          # HTTP on port 8080
  python simple_web_server.py --enable-auth             # Enable basic authentication
  python simple_web_server.py --log-headers             # Enable header logging
  python simple_web_server.py --domain example.com      # Use custom SSL certificate
        """
    )
    
    # Server configuration
    parser.add_argument('--domain', 
                        help='Domain name for SSL certificate (e.g., example.com). Uses "server" if not specified.')
    parser.add_argument('--http-port', type=int, default=80, 
                        help='HTTP port (default: 80)')
    parser.add_argument('--https-port', type=int, default=443, 
                        help='HTTPS port (default: 443)')
    
    # Authentication
    parser.add_argument('--enable-auth', action='store_true', default=False,
                        help='Enable basic authentication')
    parser.add_argument('--auth-username', type=str, default='user',
                        help='Authentication username (default: "user")')
    parser.add_argument('--auth-password', type=str, default='user',
                        help='Authentication password (default: "user")')
    
    # Logging options
    parser.add_argument('--log-headers', action='store_true', default=False,
                        help='Enable logging of request/response headers')
    parser.add_argument('--log-request-data', action='store_true', default=False,
                        help='Enable logging of processed request data')
    parser.add_argument('--log-raw-data', action='store_true', default=False,
                        help='Enable logging of raw request data (including multipart boundaries)')
    parser.add_argument('--enable-file-log', action='store_true', default=False,
                        help='Enable file logging')
    parser.add_argument('--log-file', type=str, default='log.txt',
                        help='Log file path (default: log.txt)')
    parser.add_argument('--log-level', type=str, default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        help='Log level (default: INFO)')

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.enable_file_log, args.log_file, args.log_level)

    # Display configuration
    logging.info("Server Configuration:")
    logging.info(f"  HTTP Port: {args.http_port}")
    logging.info(f"  HTTPS Port: {args.https_port}")
    logging.info(f"  Domain: {args.domain or 'server'}")
    logging.info(f"  WWW Directory: {WWW_DIR}")
    logging.info(f"  Upload Directory: {UPLOAD_DIR}")
    if args.enable_auth:
        logging.info(f"  Authentication: Enabled (user: {args.auth_username})")
    else:
        logging.info("  Authentication: Disabled")
    
    if any([args.log_headers, args.log_request_data, args.log_raw_data]):
        debug_features = []
        if args.log_headers:
            debug_features.append("headers")
        if args.log_request_data:
            debug_features.append("request-data")
        if args.log_raw_data:
            debug_features.append("raw-data")
        logging.info(f"  Debug Features: {', '.join(debug_features)}")

    # Start HTTP server in a separate thread
    http_thread = threading.Thread(
        target=run_http_server,
        args=(
            args.http_port,
            args.log_headers,
            args.log_request_data,
            args.log_raw_data,
            args.enable_auth,
            args.auth_username,
            args.auth_password,
            args.enable_file_log,
            args.log_file
        ),
        daemon=True
    )
    http_thread.start()

    # Start HTTPS server (main thread)
    try:
        run_https_server(
            args.domain,
            args.https_port,
            args.log_headers,
            args.log_request_data,
            args.log_raw_data,
            args.enable_auth,
            args.auth_username,
            args.auth_password,
            args.enable_file_log,
            args.log_file
        )
    except KeyboardInterrupt:
        logging.info("Server stopped by user")
    except Exception as e:
        logging.error(f"Server error: {e}")


if __name__ == "__main__":
    main()
