# TCP Client

A robust TCP client implementation in Python that demonstrates advanced socket programming and HTTP request handling with proper error management and SSL/TLS support.

## Description

This project implements a production-ready TCP client that can connect to web servers securely, send HTTP requests, and handle responses with proper error management. It's an excellent example of network programming best practices in Python.

## Features

- Creates secure TCP socket connections with SSL/TLS support
- Automatic protocol detection (HTTP/HTTPS)
- Configurable timeout management
- Comprehensive error handling
- Proper HTTP request/response parsing
- Support for custom HTTP headers
- Automatic hostname resolution
- Proper connection cleanup
- Type hints for better code maintainability
- Detailed logging and error reporting

## Requirements

- Python 3.x
- No additional packages required (uses built-in modules):
  - `socket` for network communication
  - `ssl` for secure connections
  - `urllib.parse` for URL parsing
  - `typing` for type hints

## Usage

### Command Line Interface

The client can be used directly from the command line with various options:

```bash
# Basic usage (connects to https://www.google.com)
python tcp.py

# Connect to a specific URL
python tcp.py https://example.com

# Connect to a domain with custom port
python tcp.py example.com -p 8080

# Disable SSL/TLS
python tcp.py example.com --no-ssl

# Set custom timeout
python tcp.py example.com -t 30

# Use different HTTP method
python tcp.py example.com -m POST

# Add custom headers
python tcp.py example.com -H "Authorization: Bearer token" -H "Custom-Header: value"
```

### Command Line Options

- `url`: Target URL to connect to (optional, defaults to https://www.google.com)
- `-p, --port`: Custom port number (overrides URL port)
- `-t, --timeout`: Connection timeout in seconds (default: 10)
- `--no-ssl`: Disable SSL/TLS (use HTTP instead of HTTPS)
- `-m, --method`: HTTP method to use (choices: GET, POST, HEAD, PUT, DELETE, default: GET)
- `-H, --header`: Add custom header (can be used multiple times, format: "Name: Value")

### Examples

1. Connect to a local development server:
```bash
python tcp.py localhost:3000
```

2. Make a POST request with custom headers:
```bash
python tcp.py api.example.com -m POST -H "Content-Type: application/json" -H "Authorization: Bearer token"
```

3. Connect to a non-standard port with SSL disabled:
```bash
python tcp.py example.com -p 8080 --no-ssl
```

4. Set a longer timeout for slow connections:
```bash
python tcp.py slow-server.com -t 30
```

## Code Structure

The main script (`tcp.py`) contains a `TCPClient` class with the following features:

### Core Functionality
- `__init__`: Initialize client with timeout and SSL settings
- `create_socket`: Create a new socket with timeout
- `connect`: Establish connection with error handling
- `send_request`: Send HTTP requests with proper headers
- `receive_response`: Receive and parse HTTP responses
- `close`: Safely close connections

### Error Handling
- Connection errors
- SSL/TLS handshake failures
- Timeout management
- DNS resolution errors
- Socket errors
- HTTP parsing errors

### Security Features
- SSL/TLS support with certificate verification
- Hostname verification
- Secure default settings
- Proper connection cleanup

## Customization

You can modify the client to:
- Change the target URL and port (via command line or code)
- Adjust timeout settings (via command line or code)
- Enable/disable SSL (via command line or code)
- Add custom HTTP headers (via command line or code)
- Modify buffer sizes
- Implement different HTTP methods (via command line or code)
- Add custom error handling
- Implement retry logic
- Add proxy support

## Example Usage

```python
from tcp import TCPClient

# Create client with custom timeout
client = TCPClient(timeout=15, use_ssl=True)

try:
    # Connect to server
    client.connect("www.example.com", 443)
    
    # Send custom request
    client.send_request(
        method="GET",
        path="/api/data",
        host="www.example.com",
        headers={
            "Authorization": "Bearer token",
            "Custom-Header": "value"
        }
    )
    
    # Get response
    response_data, headers = client.receive_response()
    
finally:
    # Always close the connection
    client.close()
```

## Production Considerations

This implementation includes several production-ready features:
- Proper error handling and reporting
- Timeout management
- SSL/TLS support with certificate verification
- Robust HTTP request/response handling
- Resource cleanup
- Type hints for better maintainability

## License

This project is open source and available under the MIT License. 