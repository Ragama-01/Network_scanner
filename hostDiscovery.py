# """
# host_discovery.py
# -----------------
# Discover live hosts on a subnet using ICMP ping.

# Requires root/admin privileges for raw socket (ICMP).
# Falls back to TCP ping on port 80 if ICMP is unavailable.

# Usage:
#     from scanner.host_discovery import discover_hosts
#     live_hosts = discover_hosts("192.168.1.0/24")
# """

import socket
import ipaddress
import concurrent.futures
import subprocess
import platform
from datetime import datetime


def ping_host_subprocess(ip: str, timeout: int = 1) -> dict | None:
    """
    Ping a host using the system's ping command.
    Works on Linux, macOS, and Windows without root privileges.
    """
    system = platform.system().lower()

    # Build the ping command per OS
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
        )
        if result.returncode == 0:
            return {"ip": ip, "state": "up", "method": "ICMP"}
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        pass  # ping not available on this system

    return None


def tcp_ping(ip: str, port: int = 80, timeout: float = 1.0) -> dict | None:
    """
    Fallback host discovery via TCP connection attempt.
    A host that refuses a connection is still 'alive'.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            # connect_ex returns 0 (open) or errno (refused/etc.)
            # Either way — the host responded, so it's alive
            if result in (0, 111, 61):  # open, connection refused (Linux/macOS)
                return {"ip": ip, "state": "up", "method": f"TCP/{port}"}
    except (socket.timeout, socket.error):
        pass
    return None


def probe_host(ip: str, timeout: float = 1.0) -> dict | None:
    """
    Try ICMP ping first, fall back to TCP ping on port 80.
    """
    result = ping_host_subprocess(ip, timeout=int(timeout))
    if result:
        return result

    # Fallback: try common ports
    for port in [80, 443, 22]:
        result = tcp_ping(ip, port=port, timeout=timeout)
        if result:
            return result

    return None


def get_hostname(ip: str) -> str:
    """Attempt reverse DNS lookup for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ""


def discover_hosts(
    network: str,
    timeout: float = 1.0,
    max_threads: int = 50,
    verbose: bool = False,
) -> dict:
    """
    Discover live hosts in a network range.

    Args:
        network:     CIDR notation e.g. "192.168.1.0/24" or single IP "192.168.1.1"
        timeout:     Seconds per probe (default: 1.0)
        max_threads: Concurrent threads (default: 50)
        verbose:     Print each discovered host

    Returns:
        Dict with list of live hosts and scan metadata.
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        return {"error": str(e), "network": network, "live_hosts": []}

    hosts = list(net.hosts())  # excludes network/broadcast addresses

    start_time = datetime.now()

    if verbose:
        print(f"\n[*] Host discovery on {network}")
        print(f"[*] Probing {len(hosts)} addresses | Threads: {max_threads}\n")

    live_hosts = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(probe_host, str(ip), timeout): str(ip)
            for ip in hosts
        }

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                # Attempt hostname resolution
                result["hostname"] = get_hostname(result["ip"])
                live_hosts.append(result)

                if verbose:
                    label = result["hostname"] or result["ip"]
                    print(
                        f"  [+] {result['ip']:<18} UP  "
                        f"({result['method']})  {label}"
                    )

    # Sort by IP address
    live_hosts.sort(key=lambda x: ipaddress.ip_address(x["ip"]))

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    if verbose:
        print(f"\n[*] Discovery complete in {duration:.2f}s")
        print(f"[*] {len(live_hosts)} host(s) found\n")

    return {
        "network": network,
        "total_probed": len(hosts),
        "live_hosts": live_hosts,
        "live_count": len(live_hosts),
        "scan_duration_seconds": round(duration, 2),
        "scanned_at": start_time.isoformat(),
    }


if __name__ == "__main__":
    import json

    # Test against localhost only — safe
    results = discover_hosts("127.0.0.1/32", verbose=True)
    print(json.dumps(results, indent=2))