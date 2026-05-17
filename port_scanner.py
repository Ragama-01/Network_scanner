

import socket #core networking ibrary
#concurrent.futires gives us ThreadPoolExecutor, which runs many port checks at the same time instead of one by one
import concurrent.futures 
# is just for recording when the scan started and how long it took.
from datetime import datetime

#lookup table
# Common ports and their typical services — used for quick labelling
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

#socket.AF_INET means IPv4, socket.SOCK_STREAM means TCP  creating a standard TCP socket.
#with socket.socket(...) as s — the with block ensures the socket is automatically closed when done, even if an error occurs
def scan_port(host: str, port: int, timeout: float = 1.0) -> dict | None:
   
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout) #s.settimeout(timeout) — if the port doesn't respond within 1 second, give up.
            result = s.connect_ex((host, port))
            if result == 0:
                service = COMMON_SERVICES.get(port, "unknown")
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                }
    except socket.timeout:
        pass  # filtered — no response
    except socket.error:
        pass  # closed or unreachable
    return None


def resolve_host(host: str) -> str | None:
    """
    Resolve a hostname to an IP address.
    Returns None if resolution fails.
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def scan_range(
    host: str,
    start_port: int = 1,
    end_port: int = 1024,
    timeout: float = 1.0,
    max_threads: int = 100,
    verbose: bool = False,
) -> dict:
    """
    Scan a range of TCP ports on a target host concurrently.

    Args:
        host:        Target IP address or hostname
        start_port:  First port to scan (default: 1)
        end_port:    Last port to scan (default: 1024)
        timeout:     Seconds to wait per port (default: 1.0)
        max_threads: Concurrent threads (default: 100)
        verbose:     Print each open port as it's found

    Returns:
        A dict with scan metadata and a list of open port results.
    """
    # Resolve hostname to IP
    ip = resolve_host(host)
    if not ip:
        return {
            "error": f"Could not resolve host: {host}",
            "host": host,
            "ip": None,
            "open_ports": [],
        }

    start_time = datetime.now()

    if verbose:
        print(f"\n[*] Starting scan on {host} ({ip})")
        print(f"[*] Port range: {start_port}-{end_port}")
        print(f"[*] Threads: {max_threads} | Timeout: {timeout}s")
        print(f"[*] Started at: {start_time.strftime('%H:%M:%S')}\n")

    open_ports = []
    port_range = range(start_port, end_port + 1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit all port scans at once
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in port_range
        }

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                if verbose:
                    print(
                        f"  [+] Port {result['port']:>5}/tcp  OPEN  "
                        f"({result['service']})"
                    )

    # Sort results by port number
    open_ports.sort(key=lambda x: x["port"])

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    scan_result = {
        "host": host,
        "ip": ip,
        "start_port": start_port,
        "end_port": end_port,
        "total_ports_scanned": end_port - start_port + 1,
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "scan_duration_seconds": round(duration, 2),
        "scanned_at": start_time.isoformat(),
    }

    if verbose:
        print(f"\n[*] Scan complete in {duration:.2f}s")
        print(f"[*] {len(open_ports)} open port(s) found\n")

    return scan_result


# ── Quick test when run directly ─────────────────────────────────────────────
if __name__ == "__main__":
    import json

    target = "scanme.nmap.org"  # Nmap's public test server — safe to scan
    results = scan_range(target, start_port=1, end_port=1024, verbose=True)

    print(json.dumps(results, indent=2))