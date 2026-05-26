

import socket


# HTTP ports get a special GET request instead of waiting for a banner
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888}

HTTP_REQUEST = (
    b"GET / HTTP/1.1\r\n"
    b"Host: {host}\r\n"
    b"User-Agent: NetworkScanner/1.0\r\n"
    b"Connection: close\r\n\r\n"
)


def grab_banner(host: str, port: int, timeout: float = 2.0) -> dict:
    """
    Connect to host:port and read the service banner.

    Returns a dict with:
        port    - the port number
        banner  - raw banner string (empty string if none received)
        error   - error message if connection failed
    """
    result = {"port": port, "banner": "", "error": None}

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            # HTTP ports: send a request and parse the Server header
            if port in HTTP_PORTS:
                request = HTTP_REQUEST.replace(b"{host}", host.encode())
                s.sendall(request)
                response = b""
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                    # Stop after headers (we only need the Server header)
                    if b"\r\n\r\n" in response:
                        break

                banner = _extract_http_banner(response.decode("utf-8", errors="ignore"))

            else:
                # Non-HTTP: just read whatever the service sends first
                banner = s.recv(1024).decode("utf-8", errors="ignore")

            result["banner"] = banner.strip()

    except socket.timeout:
        result["error"] = "timeout"
    except ConnectionRefusedError:
        result["error"] = "connection refused"
    except socket.error as e:
        result["error"] = str(e)

    return result


def _extract_http_banner(response: str) -> str:
    """
    Pull meaningful info from an HTTP response:
    status line + Server header + X-Powered-By header.
    """
    lines = response.splitlines()
    interesting = []

    if lines:
        interesting.append(lines[0])  # e.g. "HTTP/1.1 200 OK"

    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith("server:") or lower.startswith("x-powered-by:"):
            interesting.append(line.strip())

    return " | ".join(interesting)


def grab_banners(host: str, ports: list[int], timeout: float = 2.0) -> list[dict]:
    """
    Grab banners from multiple open ports on a host.

    Args:
        host:    Target IP or hostname
        ports:   List of open port numbers
        timeout: Seconds per connection

    Returns:
        List of banner result dicts, one per port.
    """
    results = []
    for port in ports:
        result = grab_banner(host, port, timeout)
        results.append(result)
    return results


def enrich_scan_results(scan_results: dict, timeout: float = 2.0) -> dict:
    """
    Take the output from port_scanner.scan_range() and add banner info
    to each open port entry.

    Args:
        scan_results: Dict returned by scan_range()
        timeout:      Banner grab timeout per port

    Returns:
        The same dict with 'banner' and 'banner_error' added to each port.
    """
    host = scan_results.get("ip") or scan_results.get("host")
    if not host or not scan_results.get("open_ports"):
        return scan_results

    for port_entry in scan_results["open_ports"]:
        port = port_entry["port"]
        banner_result = grab_banner(host, port, timeout)
        port_entry["banner"] = banner_result["banner"]
        port_entry["banner_error"] = banner_result["error"]

    return scan_results


if __name__ == "__main__":
    import json

    # Test against scanme.nmap.org — public test server
    target = "scanme.nmap.org"
    test_ports = [22, 80]

    print(f"\n[*] Grabbing banners from {target}...\n")
    results = grab_banners(target, test_ports)

    for r in results:
        print(f"  Port {r['port']:>5}: {r['banner'] or r['error']}")

    print(json.dumps(results, indent=2))