import socket
import ssl
import sys
import argparse
from urllib.parse import urlparse
import time
from typing import Optional, Tuple

class TCPClient:
    def __init__(self, timeout: int = 10, use_ssl: bool = True):
        self.timeout = timeout
        self.use_ssl = use_ssl
        self.socket = None
        self.ssl_context = None
        if use_ssl:
            self.ssl_context = ssl.create_default_context()
            # Verify certificates by default
            self.ssl_context.verify_mode = ssl.CERT_REQUIRED
            self.ssl_context.check_hostname = True

    def create_socket(self) -> None:
        """Create a new socket with timeout settings."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
        except socket.error as e:
            raise ConnectionError(f"Failed to create socket: {e}")

    def connect(self, host: str, port: int) -> None:
        """Establish connection to the server with error handling."""
        if not self.socket:
            self.create_socket()

        try:
            # Resolve hostname to IP address
            ip_address = socket.gethostbyname(host)
            self.socket.connect((ip_address, port))
            
            if self.use_ssl:
                try:
                    # Wrap socket with SSL
                    self.socket = self.ssl_context.wrap_socket(
                        self.socket,
                        server_hostname=host
                    )
                except ssl.SSLError as e:
                    raise ConnectionError(f"SSL/TLS handshake failed: {e}")
                
        except socket.gaierror as e:
            raise ConnectionError(f"Failed to resolve hostname {host}: {e}")
        except socket.timeout as e:
            raise ConnectionError(f"Connection timed out after {self.timeout} seconds: {e}")
        except socket.error as e:
            raise ConnectionError(f"Failed to connect to {host}:{port}: {e}")

    def send_request(self, method: str, path: str, host: str, headers: Optional[dict] = None) -> None:
        """Send HTTP request with proper headers and error handling."""
        if not self.socket:
            raise ConnectionError("Not connected to server")

        # Default headers
        default_headers = {
            'Host': host,
            'User-Agent': 'Python TCP Client',
            'Accept': '*/*',
            'Connection': 'close'
        }
        
        # Update with custom headers if provided
        if headers:
            default_headers.update(headers)

        # Construct HTTP request
        request_lines = [
            f"{method} {path} HTTP/1.1",
            *[f"{k}: {v}" for k, v in default_headers.items()],
            "",  # Empty line to separate headers from body
            ""   # Empty line to end request
        ]
        request = "\r\n".join(request_lines)

        try:
            self.socket.sendall(request.encode())
        except socket.error as e:
            raise ConnectionError(f"Failed to send request: {e}")

    def receive_response(self, buffer_size: int = 4096) -> Tuple[bytes, dict]:
        """Receive and parse HTTP response with error handling."""
        if not self.socket:
            raise ConnectionError("Not connected to server")

        try:
            response_data = bytearray()
            headers = {}
            header_parsed = False
            content_length = None

            while True:
                try:
                    chunk = self.socket.recv(buffer_size)
                    if not chunk:
                        break
                    
                    response_data.extend(chunk)
                    
                    # Parse headers if not done yet
                    if not header_parsed:
                        try:
                            header_end = response_data.find(b"\r\n\r\n")
                            if header_end != -1:
                                header_text = response_data[:header_end].decode()
                                header_lines = header_text.split("\r\n")
                                
                                # Parse status line
                                status_line = header_lines[0]
                                version, status_code, reason = status_line.split(" ", 2)
                                
                                # Parse headers
                                for line in header_lines[1:]:
                                    if ":" in line:
                                        key, value = line.split(":", 1)
                                        headers[key.strip()] = value.strip()
                                
                                # Get content length if present
                                content_length = int(headers.get('Content-Length', 0))
                                header_parsed = True
                                
                                # Remove headers from response data
                                response_data = response_data[header_end + 4:]
                                
                                # If no content length, we're done
                                if content_length == 0:
                                    break
                        except Exception as e:
                            raise ConnectionError(f"Failed to parse headers: {e}")
                    
                    # Check if we've received all the data
                    if header_parsed and content_length and len(response_data) >= content_length:
                        break
                        
                except socket.timeout:
                    raise ConnectionError(f"Timeout while receiving data after {self.timeout} seconds")
                except socket.error as e:
                    raise ConnectionError(f"Error while receiving data: {e}")

            return bytes(response_data), headers

        except Exception as e:
            raise ConnectionError(f"Failed to receive response: {e}")

    def close(self) -> None:
        """Safely close the connection."""
        if self.socket:
            try:
                self.socket.close()
            except socket.error as e:
                print(f"Warning: Error while closing socket: {e}", file=sys.stderr)
            finally:
                self.socket = None

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='TCP Client with SSL/TLS support for making HTTP requests'
    )
    parser.add_argument(
        'url',
        nargs='?',
        default='https://www.google.com',
        help='URL to connect to (default: https://www.google.com)'
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        help='Custom port number (overrides URL port)'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=10,
        help='Connection timeout in seconds (default: 10)'
    )
    parser.add_argument(
        '--no-ssl',
        action='store_true',
        help='Disable SSL/TLS (use HTTP instead of HTTPS)'
    )
    parser.add_argument(
        '-m', '--method',
        default='GET',
        choices=['GET', 'POST', 'HEAD', 'PUT', 'DELETE'],
        help='HTTP method to use (default: GET)'
    )
    parser.add_argument(
        '-H', '--header',
        action='append',
        help='Add custom header (format: "Name: Value")'
    )
    return parser.parse_args()

def main():
    # Parse command line arguments
    args = parse_arguments()
    
    try:
        # Parse URL
        parsed_url = urlparse(args.url)
        if not parsed_url.scheme:
            # If no scheme provided, use http or https based on --no-ssl flag
            scheme = 'http' if args.no_ssl else 'https'
            url = f"{scheme}://{args.url}"
            parsed_url = urlparse(url)
        
        host = parsed_url.netloc
        path = parsed_url.path or "/"
        
        # Determine port
        if args.port:
            port = args.port
        else:
            port = parsed_url.port or (80 if args.no_ssl else 443)
        
        # Determine SSL usage
        use_ssl = not args.no_ssl and parsed_url.scheme == 'https'
        
        # Parse custom headers
        headers = {}
        if args.header:
            for header in args.header:
                try:
                    name, value = header.split(':', 1)
                    headers[name.strip()] = value.strip()
                except ValueError:
                    print(f"Warning: Invalid header format '{header}'. Skipping.", file=sys.stderr)

        # Create and configure client
        client = TCPClient(timeout=args.timeout, use_ssl=use_ssl)
        
        try:
            # Connect to server
            print(f"Connecting to {host}:{port}...")
            client.connect(host, port)
            
            # Send request
            print(f"Sending {args.method} request...")
            client.send_request(args.method, path, host, headers)
            
            # Receive response
            print("Receiving response...")
            response_data, response_headers = client.receive_response()
            
            # Print response
            print("\nResponse Headers:")
            for key, value in response_headers.items():
                print(f"{key}: {value}")
            
            print("\nResponse Body:")
            print(response_data.decode(errors='replace'))
            
        finally:
            # Always close the connection
            client.close()
            
    except ConnectionError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 