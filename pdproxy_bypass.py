import http.server
import socketserver
import urllib.request
import urllib.parse
import ipaddress
import socket
import select
import threading
import sys

PORT = 8888

# Local fake-ip DNS answers every domain with an address in 198.18.0.0/15;
# the real target is reached upstream when connecting to that address.
_FAKE_IP_NET = ipaddress.ip_network('198.18.0.0/15')

def _validate_forward_target(host):
    """Anti-SSRF (CWE-918): resolve host and reject non-public targets.

    Residual: the forwarding request performs its own DNS lookup, so a
    TOCTOU rebinding window remains; accepted for a loopback-only demo
    proxy (documented in the security report).
    """
    checked = 0
    for info in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(info[4][0].split('%')[0])
        checked += 1
        if ip in _FAKE_IP_NET:
            return
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified
                or not ip.is_global):
            raise ValueError(f"blocked non-public target: {host} -> {ip}")
    if checked == 0:
        raise ValueError(f"cannot resolve host: {host}")

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Print to stderr so it shows up in the console
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          format % args))

    def do_GET(self):
        # Handle ping request from PanDownload to check proxy
        if self.path == 'http://pandownload.com/api/ping':
             self.send_response(200)
             self.end_headers()
             return
        self.handle_request(method='GET')

    def do_POST(self):
        self.handle_request(method='POST')

    def handle_request(self, method):
        url = self.path
        print(f"[{method}] Request: {url}")

        # Intercept PanDownload API
        if "pandownload.com" in url:
            print(f"Intercepting PanDownload Request: {url}")
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            # Standard success response for init, login, etc.
            response_body = b'{"code":0, "errno":0, "message":"success", "version":"2.2.2", "clienttype":0, "data": {"version": "2.2.2", "user_id": 123456, "token": "fake_token"}}'
            self.wfile.write(response_body)
            return

        # Handle other requests (Forwarding)
        # Note: This is a simplified proxy. 
        # Ideally we should parse the URL properly.
        # Anti-SSRF (CWE-918): only forward http/https to public targets.
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            self.send_error(403, "Forbidden: only http/https targets are allowed")
            return
        try:
            _validate_forward_target(parsed.hostname)
        except (ValueError, socket.gaierror) as e:
            self.send_error(403, f"Forbidden: {e}")
            return

        try:
            if method == 'GET':
                req = urllib.request.Request(url)
            else:
                # For POST, read data
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                req = urllib.request.Request(url, data=post_data)
            
            # Copy headers
            for key, value in self.headers.items():
                if key.lower() not in ['host', 'proxy-connection']:
                    req.add_header(key, value)

            with urllib.request.urlopen(req, timeout=10) as response:
                self.send_response(response.status)
                for key, value in response.headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(response.read())
                
        except Exception as e:
            print(f"Proxy Error for {url}: {e}")
            self.send_error(502, f"Bad Gateway: {e}")

    def do_CONNECT(self):
        # Handle HTTPS Tunneling
        print(f"[CONNECT] {self.path}")
        target = self.path
        if target.startswith('['):
            # IPv6 literal: [::1]:443
            host = target[1:target.index(']')]
            rest = target[target.index(']') + 1:]
            port = int(rest[1:]) if rest.startswith(':') else 443
        elif ':' in target:
            host, _, port_s = target.rpartition(':')
            if not host:
                host = port_s
            port = int(port_s) if port_s.isdigit() else 443
        else:
            host, port = target, 443

        # Anti-SSRF (CWE-918): refuse tunneling to loopback/private/reserved.
        try:
            _validate_forward_target(host)
        except (ValueError, socket.gaierror) as e:
            self.send_error(403, f"Forbidden: {e}")
            return

        # Direct tunnel for baidu domains - try to let them pass through
        # But since we can't modify headers inside SSL, this relies on PanDownload sending valid headers initially
        
        try:
            remote_sock = socket.create_connection((host, port), timeout=10)
            self.send_response(200, 'Connection Established')
            self.end_headers()

            # Pipe data
            self.pipe_sockets(self.connection, remote_sock)
        except Exception as e:
            print(f"Connect Error to {host}:{port} -> {e}")
            self.send_error(502, f"Bad Gateway: {e}")

    def pipe_sockets(self, sock1, sock2):
        sockets = [sock1, sock2]
        while True:
            try:
                r, _, _ = select.select(sockets, [], [], 10)
                if not r: break
                for s in r:
                    data = s.recv(8192)
                    if not data: return
                    if s is sock1:
                        sock2.sendall(data)
                    else:
                        sock1.sendall(data)
            except:
                break
        try:
            sock1.close()
            sock2.close()
        except:
            pass

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

def main():
    # Allow address reuse
    socketserver.TCPServer.allow_reuse_address = True
    
    try:
        server = ThreadingHTTPServer(('127.0.0.1', PORT), ProxyHandler)
        print(f"Python Fake Proxy listening on port {PORT}...")
        server.serve_forever()
    except Exception as e:
        print(f"Failed to start server: {e}")

if __name__ == "__main__":
    main()
