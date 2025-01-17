import http.server
import socketserver
import ssl
import os
import threading
import shutil
from functools import partial
import base64
import cgi
import io
import re
import argparse
import logging
import sys
import warnings

WWW_DIR = os.path.join(os.getcwd(), 'www')
DOMAIN_DIR = os.path.join(os.getcwd(), 'domain')
UPLOAD_DIR = os.path.join(WWW_DIR, 'uploads')

# Create the www directory and copy index.html
if not os.path.exists(WWW_DIR):
    os.makedirs(WWW_DIR)
index_src = os.path.join(os.path.dirname(__file__), 'index.html')
index_dst = os.path.join(WWW_DIR, 'index.html')
if os.path.exists(index_src) and not os.path.exists(index_dst):
    shutil.copy(index_src, index_dst)

# Ensure the upload directory exists
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# Default username and password
USERNAME = 'user'
PASSWORD = 'user'

BYTE_RANGE_RE = re.compile(r'bytes=(\d+)-(\d+)?$')

def parse_byte_range(byte_range):
    '''Returns the two numbers in 'bytes=123-456', otherwise raises ValueError.'''
    if byte_range.strip() == '':
        return None, None

    m = BYTE_RANGE_RE.match(byte_range)
    if not m:
        raise ValueError('Invalid byte range %s' % byte_range)

    first, last = [x and int(x) for x in m.groups()]
    if last and last < first:
        raise ValueError('Invalid byte range %s' % byte_range)
    return first, last

class RangeRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom request handler supporting Range requests and basic authentication.
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
        self.raw_request = ""  # Initialize raw_request
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format, *args):
        """Override to use logging instead of print."""
        message = "%s - - [%s] %s\n" % (
            self.client_address[0],
            self.log_date_time_string(),
            format % args
        )
        logging.info(message.strip())

    def send_header(self, keyword, value):
        super().send_header(keyword, value)
        self.response_headers[keyword] = value

    def end_headers(self):
        super().end_headers()
        if self.log_headers:
            logging.info("Sent Headers:")
            for header, value in self.response_headers.items():
                logging.info(f"{header}: {value}")
            logging.info("----------------------------")
        self.response_headers.clear()

    def authenticate(self):
        if not self.enable_auth:
            return True

        auth_header = self.headers.get('Authorization')
        if auth_header is None:
            self.request_authentication()
            return False

        try:
            auth_type, encoded_credentials = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                self.request_authentication()
                return False

            decoded_credentials = base64.b64decode(encoded_credentials.strip()).decode('utf-8')
            username, password = decoded_credentials.split(':', 1)

            if username == self.auth_username and password == self.auth_password:
                return True
            else:
                self.request_authentication()
                return False
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            # Log the original request upon authentication failure
            logging.error("----- Original Request -----")
            logging.error(self.raw_request)
            logging.error("----------------------------")
            self.request_authentication()
            return False

    def request_authentication(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Protected"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Authentication required.')

    def send_head(self):
        if self.log_headers:
            logging.info("Received Headers:")
            for header, value in self.headers.items():
                logging.info(f"{header}: {value}")

        # Reconstruct the raw_request for GET
        self.raw_request = f"{self.requestline}\r\n"
        for header, value in self.headers.items():
            self.raw_request += f"{header}: {value}\r\n"
        self.raw_request += "\r\n"

        if self.enable_auth and not self.authenticate():
            # Authentication failed; raw_request has been logged in authenticate()
            return None

        if 'Range' not in self.headers:
            self.range = None
            return super().send_head()

        try:
            self.range = parse_byte_range(self.headers['Range'])
        except ValueError as e:
            self.send_error(400, 'Invalid byte range')
            # Log the original request upon error
            logging.error("----- Original Request -----")
            logging.error(self.raw_request)
            logging.error("----------------------------")
            return None

        first, last = self.range
        path = self.translate_path(self.path)
        try:
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, 'File not found')
            # Log the original request upon error
            logging.error("----- Original Request -----")
            logging.error(self.raw_request)
            logging.error("----------------------------")
            return None

        fs = os.fstat(f.fileno())
        file_len = fs.st_size
        if first >= file_len:
            self.send_error(416, 'Requested Range Not Satisfiable')
            f.close()
            # Log the original request upon error
            logging.error("----- Original Request -----")
            logging.error(self.raw_request)
            logging.error("----------------------------")
            return None

        self.send_response(206)
        ctype = self.guess_type(path)
        self.send_header('Content-type', ctype)
        self.send_header('Accept-Ranges', 'bytes')

        if last is None or last >= file_len:
            last = file_len - 1
        response_length = last - first + 1

        self.send_header('Content-Range',
                         f'bytes {first}-{last}/{file_len}')
        self.send_header('Content-Length', str(response_length))
        self.send_header('Last-Modified', self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f

    def copyfile(self, source, outputfile):
        if not self.range:
            return super().copyfile(source, outputfile)

        start, stop = self.range
        copy_byte_range(source, outputfile, start, stop)

    def do_POST(self):
        if self.log_headers:
            logging.info("Received Headers:")
            for header, value in self.headers.items():
                try:
                    logging.info(f"{header}: {value}")
                except UnicodeEncodeError as e:
                    logging.error(f"Header {header} encoding error: {e}")
                    logging.info(f"{header}: {value.encode('utf-8', errors='replace').decode('utf-8')}")

        # Reconstruct the raw_request for POST (including body)
        self.raw_request = f"{self.requestline}\r\n"
        for header, value in self.headers.items():
            self.raw_request += f"{header}: {value}\r\n"
        self.raw_request += "\r\n"

        if self.enable_auth and not self.authenticate():
            # Authentication failed; raw_request has been logged in authenticate()
            return

        content_length = int(self.headers.get('Content-Length', 0))
        content_type = self.headers.get('Content-Type', '')
        post_data = self.rfile.read(content_length)

        # Append the body to raw_request for logging
        try:
            raw_body = post_data.decode('utf-8', errors='replace')
        except:
            raw_body = "<binary data>"
        self.raw_request += raw_body

        if self.log_raw_data:
            logging.info("----- Raw Request -----")
            logging.info(self.raw_request)
            logging.info("-----------------------")

        if 'multipart/form-data' in content_type:
            boundary = content_type.split('boundary=')[-1]
            if not boundary:
                self.send_error(400, "Bad Request: Missing boundary in multipart/form-data")
                # Log the original request upon error
                logging.error("----- Original Request -----")
                logging.error(self.raw_request)
                logging.error("----------------------------")
                return
            environ = {'REQUEST_METHOD': 'POST'}
            fs = cgi.FieldStorage(
                fp=io.BytesIO(post_data),
                headers=self.headers,
                environ=environ,
                keep_blank_values=True
            )
            if 'file' in fs:
                file_field = fs['file']
                if file_field.filename:
                    filename = os.path.basename(file_field.filename)
                    file_path = os.path.join(UPLOAD_DIR, filename)
                    try:
                        with open(file_path, 'wb') as output_file:
                            file_content = file_field.file.read()
                            output_file.write(file_content)
                        if self.enable_file_logging:
                            logging.info(f"File saved: {file_path}")
                    except Exception as e:
                        logging.error(f"Error saving file: {e}")
                        self.send_error(500, "Internal Server Error: Unable to save file")
                        # Log the original request upon error
                        logging.error("----- Original Request -----")
                        logging.error(self.raw_request)
                        logging.error("----------------------------")
                        return
                else:
                    self.send_error(400, "Bad Request: No filename provided")
                    # Log the original request upon error
                    logging.error("----- Original Request -----")
                    logging.error(self.raw_request)
                    logging.error("----------------------------")
                    return
            else:
                self.send_error(400, "Bad Request: No file field in form")
                # Log the original request upon error
                logging.error("----- Original Request -----")
                logging.error(self.raw_request)
                logging.error("----------------------------")
                return

        if self.log_request_data and 'multipart/form-data' not in content_type:
            try:
                decoded_post = post_data.decode('utf-8', errors='replace')
            except:
                decoded_post = "<binary data>"
            logging.info("----- POST Data -----")
            logging.info(decoded_post)
            logging.info("---------------------")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"POST received and file uploaded.")

def copy_byte_range(infile, outfile, start=None, stop=None, bufsize=16*1024):
    '''Similar to shutil.copyfileobj but only copies a specific range of the stream.'''

    if start is not None:
        infile.seek(start)
    while True:
        to_read = min(bufsize, stop + 1 - infile.tell() if stop is not None else bufsize)
        buf = infile.read(to_read)
        if not buf:
            break
        outfile.write(buf)

def create_ssl_context(domain):
    if not domain:
        domain = "server"
    cert_path = os.path.join(DOMAIN_DIR, domain, f"{domain}.pem")
    key_path = os.path.join(DOMAIN_DIR, domain, f"{domain}.key")
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        logging.error(f"Cannot find certificate or key for domain '{domain}'.")
        return None
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    return context

def run_https_server(domain, port, log_headers, log_request_data, log_raw_data,
                    enable_auth, auth_username, auth_password,
                    enable_file_logging, log_file_path):
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
        directory=WWW_DIR  # Set directory to WWW_DIR
    )
    httpd = socketserver.TCPServer(("", port), handler)
    context = create_ssl_context(domain)
    if context:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        logging.info(f"[HTTPS] Serving on port {port} (Domain='{domain if domain else 'server'}')...")
        httpd.serve_forever()
    else:
        logging.error("Unable to create SSL context.")

def run_http_server(port, log_headers, log_request_data, log_raw_data,
                   enable_auth, auth_username, auth_password,
                   enable_file_log, log_file_path):
    handler = partial(
        RangeRequestHandler,
        log_headers=log_headers,
        log_request_data=log_request_data,
        log_raw_data=log_raw_data,
        enable_auth=enable_auth,
        auth_username=auth_username,
        auth_password=auth_password,
        enable_file_logging=enable_file_log,  # Use enable_file_log
        log_file_path=log_file_path,
        directory=WWW_DIR  # Set directory to WWW_DIR
    )
    httpd = socketserver.TCPServer(("", port), handler)
    logging.info(f"[HTTP] Serving on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simple HTTP/HTTPS server with optional basic authentication and file upload')
    parser.add_argument('--domain', required=False,
                        help='Domain name, e.g., example.com. If not specified, server.pem and server.key will be used.')
    parser.add_argument('--http-port', type=int, default=80, help='HTTP port (default: 80)')
    parser.add_argument('--https-port', type=int, default=443, help='HTTPS port (default: 443)')
    parser.add_argument('--log-headers', action='store_true', default=False,
                        help='Enable logging of request/response headers')
    parser.add_argument('--log-request-data', action='store_true', default=False,
                        help='Enable logging of processed request data (e.g., parsed POST data)')
    parser.add_argument('--log-raw-data', action='store_true', default=False,
                        help='Enable logging of raw request data (including multipart boundaries)')
    parser.add_argument('--enable-auth', action='store_true', default=False,
                        help='Enable basic authentication')
    parser.add_argument('--auth-username', type=str, default='user',
                        help='Authentication username (effective when authentication is enabled). Default is "user".')
    parser.add_argument('--auth-password', type=str, default='user',
                        help='Authentication password (effective when authentication is enabled). Default is "user".')
    parser.add_argument('--log-file', type=str, default='log.txt',
                        help='Log file path. Used only when logging is enabled.')
    parser.add_argument('--enable-file-log', action='store_true', default=False,
                        help='Enable file logging.')

    args = parser.parse_args()

    # Configure logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler
    if args.enable_file_log:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_path = os.path.join(script_dir, args.log_file)
        file_handler = logging.FileHandler(log_path, mode='w', encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

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