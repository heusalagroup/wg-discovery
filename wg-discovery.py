#!/usr/bin/env python3
"""
Simple dynamic WireGuard endpoint discovery service.

- Exposes current endpoint data via GET /v1/endpoints.
- Uses source IP filtering to restrict access (if provided).
- All configuration is provided via command‑line arguments.
- Automatically determines the local IP of the selected WireGuard interface
  if --bind-ip is not provided.
- Automatically adds the bind IP to the allowed source IPs.
- Returns responses and error messages in JSON format.
- Optionally drops privileges to a specified user and group.
- Optionally runs an auto‑discovery process that:
    1. Retrieves the current remote endpoints using 'wg show <interface> endpoints',
    2. Retrieves each peer’s internal WireGuard IP via 'wg show <interface> allowed-ips',
    3. Pings each peer via HTTP GET /v1/endpoints on its allowed IP,
    4. For inactive peers, queries active discovery peers (using their GET /v1/endpoints response)
       for updated endpoint information, and
    5. If a discovery peer returns a non-null endpoint that differs from the current remote endpoint,
       updates the local configuration and logs both the previous and new endpoint values.
- The GET request for /v1/endpoints returns cached data if it is fresh (less than --cache-freshness seconds old);
  otherwise, it triggers an on-demand cache update and waits (up to --cache-wait-timeout seconds) for fresh data.

Intended to run as a systemd service on Linux (adaptable to macOS via launchd).

Usage example:
    sudo python3 wg_endpoint_service.py --wg-interface wg0 --port 51820 \
      --allowed-ips 10.220.0.19,10.220.0.25 --use-sudo --user nobody --group nogroup \
      --auto-discovery --discovery-interval 60 --max-workers 10 \
      --cache-freshness 15 --cache-wait-timeout 30 --log-level DEBUG
"""

import http.server
import socketserver
import subprocess
import json
import logging
import argparse
import socket
import sys
import struct
import fcntl
import re
import os
import pwd
import grp
from urllib.parse import urlparse
from functools import partial
import threading
import time
import urllib.request
from threading import Timer
import concurrent.futures

# Global cache variables and events.
cached_endpoints = {}
last_cache_update_time = 0
cache_lock = threading.Lock()
cache_update_event = threading.Event()
cache_updated_event = threading.Event()

# Configurable thresholds.
CACHE_FRESHNESS_THRESHOLD = 15  # seconds: cache is fresh if updated within this many seconds.
CACHE_WAIT_TIMEOUT = 30         # seconds: maximum time to wait for a cache update.


def get_interface_ip(ifname):
    """
    Get the IPv4 address assigned to the network interface ifname.
    Uses ioctl on Linux and ifconfig parsing on macOS.
    """
    if sys.platform.startswith("darwin"):
        try:
            output = subprocess.check_output(["ifconfig", ifname], text=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Could not run ifconfig for interface {ifname}: {e}")
        match = re.search(r'\s+inet\s+(\d+\.\d+\.\d+\.\d+)', output)
        if match:
            return match.group(1)
        else:
            raise RuntimeError(f"Could not determine IP for interface {ifname} from ifconfig output")
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ip_addr = socket.inet_ntoa(
                fcntl.ioctl(
                    s.fileno(),
                    0x8915,  # SIOCGIFADDR
                    struct.pack('256s', ifname[:15].encode('utf-8'))
                )[20:24]
            )
        except Exception as e:
            raise RuntimeError(f"Could not determine IP for interface {ifname}: {e}")
        return ip_addr


def drop_privileges(user, group):
    """
    Drop root privileges by switching to the specified user and group.
    If group is not specified, use the user's primary group.
    """
    if os.getuid() != 0:
        return
    try:
        pw_record = pwd.getpwnam(user)
    except KeyError:
        raise RuntimeError(f"User '{user}' not found; cannot drop privileges.")
    uid = pw_record.pw_uid
    if group:
        try:
            gr_record = grp.getgrnam(group)
            gid = gr_record.gr_gid
        except KeyError:
            raise RuntimeError(f"Group '{group}' not found; cannot drop privileges.")
    else:
        gid = pw_record.pw_gid
    os.setgid(gid)
    os.setuid(uid)
    logging.info("Dropped privileges to user %s (UID: %d, GID: %d)", user, uid, gid)


def wg_show_endpoints(wg_interface, use_sudo=False):
    """
    Run 'wg show <interface> endpoints' and parse its output.

    Expected sample output (tab-separated):

        <peer_key1>    (none)
        <peer_key2>    1.2.3.4:51820
        <peer_key3>    5.6.7.8:51820

    Returns a dictionary in the form:
      {
          "<peer_key1>": null,
          "<peer_key2>": "1.2.3.4:51820",
          "<peer_key3>": "5.6.7.8:51820"
      }
    """
    cmd = ["wg", "show", wg_interface, "endpoints"]
    if use_sudo:
        cmd = ["sudo"] + cmd
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    endpoints = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) != 2:
            continue
        peer_key, endpoint = parts
        if endpoint.lower() == "(none)":
            endpoints[peer_key] = None
        else:
            endpoints[peer_key] = endpoint
    return endpoints


def wg_show_allowed_ips(wg_interface, use_sudo=False):
    """
    Run 'wg show <interface> allowed-ips' and parse its output.

    Expected sample output (tab-separated):

        <peer_key1>    10.220.0.19/32
        <peer_key2>    10.220.0.25/32
        ...

    Returns a dictionary mapping each peer's public key to its allowed IP (without the CIDR).
    """
    cmd = ["wg", "show", wg_interface, "allowed-ips"]
    if use_sudo:
        cmd = ["sudo"] + cmd
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    allowed = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) != 2:
            continue
        peer_key, ip_cidr = parts
        ip = ip_cidr.split('/')[0]
        allowed[peer_key] = ip
    return allowed


def wg_set_peer_endpoint(wg_interface, peer_key, new_endpoint, use_sudo=False):
    """
    Run 'wg set <interface> peer <peer_key> endpoint <new_endpoint>'.
    """
    cmd = ["wg", "set", wg_interface, "peer", peer_key, "endpoint", new_endpoint]
    if use_sudo:
        cmd = ["sudo"] + cmd
    subprocess.run(cmd, check=True)


def cache_update_worker(wg_interface, use_sudo):
    """
    Background worker that waits for an event trigger to update the cache.
    When triggered by a GET request, it updates the global cached_endpoints and last_cache_update_time,
    then signals that fresh data is available.
    """
    global cached_endpoints, last_cache_update_time
    while True:
        cache_update_event.wait()
        try:
            endpoints = wg_show_endpoints(wg_interface, use_sudo)
            with cache_lock:
                cached_endpoints = endpoints
                last_cache_update_time = time.time()
            cache_updated_event.set()
            logging.debug("Cache updated on demand: %s", endpoints)
        except Exception as e:
            logging.error("Failed to update endpoints cache on demand: %s", e)
            cache_updated_event.set()
        finally:
            cache_update_event.clear()


class WGEndpointHandler(http.server.BaseHTTPRequestHandler):
    """
    GET /v1/endpoints returns cached remote endpoint information.
    If the cache is older than --cache-freshness seconds, the request triggers a cache update
    and waits (up to --cache-wait-timeout seconds) for fresh data.
    """

    def __init__(self, *args, wg_interface, allowed_ips, use_sudo, **kwargs):
        self.wg_interface = wg_interface
        self.allowed_ips = allowed_ips
        self.use_sudo = use_sudo
        super().__init__(*args, **kwargs)

    def _send_json_response(self, code, data):
        response = json.dumps(data)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(response.encode("utf-8"))

    def _check_source_ip(self):
        if not self.allowed_ips:
            return True
        client_ip = self.client_address[0]
        if client_ip not in self.allowed_ips:
            logging.warning("Rejected connection from unauthorized IP: %s", client_ip)
            self._send_json_response(403, {"error": "Forbidden"})
            return False
        return True

    def do_GET(self):
        if not self._check_source_ip():
            return
        parsed = urlparse(self.path)
        # GET /v1/endpoints returns remote endpoint information.
        if parsed.path == "/v1/endpoints":
            with cache_lock:
                age = time.time() - last_cache_update_time
            if age < CACHE_FRESHNESS_THRESHOLD:
                with cache_lock:
                    current_cache = dict(cached_endpoints)
                self._send_json_response(200, current_cache)
            else:
                # Trigger cache update and wait for fresh data.
                cache_update_event.set()
                if not cache_updated_event.wait(timeout=CACHE_WAIT_TIMEOUT):
                    self._send_json_response(500, {"error": "Cache update timeout"})
                    return
                else:
                    cache_updated_event.clear()
                    with cache_lock:
                        current_cache = dict(cached_endpoints)
                    self._send_json_response(200, current_cache)
        else:
            self._send_json_response(404, {"error": "Not Found"})

    def log_message(self, format, *args):
        logging.info("%s - %s", self.address_string(), format % args)


def query_peer(peer_key, allowed_ip, local_port):
    """
    Query a peer's /v1/endpoints URL.
    Returns a tuple: (peer_key, allowed_ip, success flag, error message).
    """
    url = f"http://{allowed_ip}:{local_port}/v1/endpoints"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            if response.status == 200:
                return (peer_key, allowed_ip, True, "")
    except Exception as e:
        return (peer_key, allowed_ip, False, str(e))


def query_peer_data(url):
    """
    Query a given URL and return JSON data.
    """
    with urllib.request.urlopen(url, timeout=5) as response:
        if response.status == 200:
            return json.loads(response.read().decode("utf-8"))
    return None


def run_auto_discovery(wg_interface, local_port, use_sudo, discovery_interval, max_workers):
    """
    Event-driven auto-discovery: perform one iteration of the auto-discovery process,
    then reschedule itself using a Timer so that iterations occur approximately every discovery_interval seconds.
    1. Retrieve the current remote endpoints.
    2. Retrieve the allowed IPs mapping.
    3. In parallel, ping each peer using its allowed IP.
    4. For each inactive peer, in parallel query discovery peers for updated endpoints.
    5. If an updated endpoint is found (and differs from the current remote endpoint),
       update the local configuration and log the change (showing both the previous and new endpoints).
    6. Log statistics and schedule the next run.
    """
    start_time = time.time()
    try:
        remote_endpoints = wg_show_endpoints(wg_interface, use_sudo)
    except Exception as e:
        elapsed = time.time() - start_time
        logging.error("Auto-discovery iteration failed to get remote endpoints (completed in %.2f s): %s", elapsed, e)
        next_run = max(0, discovery_interval - elapsed)
        Timer(next_run, run_auto_discovery, args=(wg_interface, local_port, use_sudo, discovery_interval, max_workers)).start()
        return

    try:
        allowed_ips_map = wg_show_allowed_ips(wg_interface, use_sudo)
    except Exception as e:
        elapsed = time.time() - start_time
        logging.error("Auto-discovery iteration failed to get allowed IPs (completed in %.2f s): %s", elapsed, e)
        next_run = max(0, discovery_interval - elapsed)
        Timer(next_run, run_auto_discovery, args=(wg_interface, local_port, use_sudo, discovery_interval, max_workers)).start()
        return

    total_peers = len(allowed_ips_map)
    active_count = 0
    inactive_count = 0
    updated_count = 0
    discovery_peers = {}

    # Use ThreadPoolExecutor to query peers in parallel.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(query_peer, peer_key, allowed_ip, local_port): peer_key
                   for peer_key, allowed_ip in allowed_ips_map.items()}
        for future in concurrent.futures.as_completed(futures):
            peer_key, allowed_ip, success, err = future.result()
            if success:
                active_count += 1
                discovery_peers[peer_key] = allowed_ip
            else:
                inactive_count += 1

    # For each inactive peer, query discovery peers in parallel.
    for peer_key in remote_endpoints:
        old_endpoint = remote_endpoints.get(peer_key)
        if old_endpoint is None:
            continue
        if peer_key in discovery_peers:
            continue  # Skip active peers.
        new_endpoint = None
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(query_peer_data, f"http://{disc_allowed_ip}:{local_port}/v1/endpoints"): disc_key
                       for disc_key, disc_allowed_ip in allowed_ips_map.items() if disc_key != peer_key}
            for future in concurrent.futures.as_completed(futures):
                disc_key = futures[future]
                try:
                    disc_data = future.result()
                    if disc_data and peer_key in disc_data and disc_data[peer_key]:
                        candidate = disc_data[peer_key]
                        if candidate != old_endpoint:
                            new_endpoint = candidate
                            logging.info("Found updated endpoint for peer %s from discovery node %s: old: %s, new: %s",
                                         peer_key, disc_key, old_endpoint, new_endpoint)
                            break
                except Exception as e:
                    logging.debug("Error querying discovery node %s: %s", disc_key, e)
        if new_endpoint and new_endpoint != old_endpoint:
            try:
                wg_set_peer_endpoint(wg_interface, peer_key, new_endpoint, use_sudo)
                logging.info("Updated peer %s endpoint from %s to %s", peer_key, old_endpoint, new_endpoint)
                updated_count += 1
            except Exception as e:
                logging.error("Failed to update peer %s (old: %s, new: %s): %s", peer_key, old_endpoint, new_endpoint, e)

    elapsed = time.time() - start_time
    logging.info("Auto-discovery statistics: total peers: %d, active: %d, inactive: %d, discovery peers: %d, updated: %d, completed in: %.2f s",
                 total_peers, active_count, inactive_count, len(discovery_peers), updated_count, elapsed)
    next_run = max(0, discovery_interval - elapsed)
    Timer(next_run, run_auto_discovery, args=(wg_interface, local_port, use_sudo, discovery_interval, max_workers)).start()


def run_server(bind_ip, port, wg_interface, allowed_ips, use_sudo, drop_user, drop_group,
               auto_discovery, discovery_interval, max_workers):
    handler_class = partial(WGEndpointHandler,
                            wg_interface=wg_interface,
                            allowed_ips=allowed_ips,
                            use_sudo=use_sudo)
    with socketserver.TCPServer((bind_ip, port), handler_class) as httpd:
        logging.info("Starting WG endpoint discovery service on http://%s:%d/", bind_ip, port)
        if drop_user:
            try:
                drop_privileges(drop_user, drop_group)
            except Exception as e:
                logging.error("Failed to drop privileges: %s", e)
                sys.exit(1)
        # Start the cache update worker thread (event-driven).
        cache_thread = threading.Thread(target=cache_update_worker, args=(wg_interface, use_sudo))
        cache_thread.daemon = True
        cache_thread.start()
        logging.debug("Cache update worker thread started.")
        if auto_discovery:
            run_auto_discovery(wg_interface, port, use_sudo, discovery_interval, max_workers)
            logging.debug("Auto-discovery process started.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.info("Shutting down WG endpoint discovery service")
            httpd.server_close()


def parse_args():
    parser = argparse.ArgumentParser(description='Dynamic WireGuard endpoint service')
    parser.add_argument('--wg-interface', default='wg0', help='Name of the WireGuard interface (default: wg0)')
    parser.add_argument('--bind-ip', default=None,
                        help='IP address to bind the HTTP server to (default: IP of the WG interface)')
    parser.add_argument('--port', type=int, default=51820, help='Port number for the HTTP server (default: 51820)')
    parser.add_argument('--allowed-ips', default='',
                        help='Comma-separated list of allowed source IP addresses (default: empty, will add bind IP automatically)')
    parser.add_argument('--use-sudo', action='store_true', help='Use sudo when running wg commands (default: False)')
    parser.add_argument('--user', default='', help='Username to drop privileges to (optional)')
    parser.add_argument('--group', default='', help='Groupname to drop privileges to (optional; defaults to user\'s primary group if not specified)')
    parser.add_argument('--auto-discovery', action='store_true', help='Enable auto-discovery of peer endpoints (default: disabled)')
    parser.add_argument('--discovery-interval', type=int, default=60,
                        help='Interval (in seconds) between auto-discovery runs (default: 60)')
    parser.add_argument('--cache-freshness', type=int, default=15,
                        help='Cache is considered fresh if updated within this many seconds (default: 15)')
    parser.add_argument('--cache-wait-timeout', type=int, default=30,
                        help='Maximum time (in seconds) to wait for a cache update (default: 30)')
    parser.add_argument('--max-workers', type=int, default=10,
                        help='Maximum number of worker threads for parallel queries (default: 10)')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level (default: INFO)')
    return parser.parse_args()


def main():
    args = parse_args()
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError("Invalid log level: %s" % args.log_level)
    logging.basicConfig(level=numeric_level, format='%(asctime)s %(levelname)s: %(message)s')

    global CACHE_FRESHNESS_THRESHOLD, CACHE_WAIT_TIMEOUT
    CACHE_FRESHNESS_THRESHOLD = args.cache_freshness
    CACHE_WAIT_TIMEOUT = args.cache_wait_timeout

    wg_interface = args.wg_interface

    if args.bind_ip:
        bind_ip = args.bind_ip
    else:
        try:
            bind_ip = get_interface_ip(wg_interface)
        except Exception as e:
            logging.error("Could not determine IP for interface %s: %s", wg_interface, e)
            sys.exit(1)

    port = args.port
    allowed_ips = {ip.strip() for ip in args.allowed_ips.split(',') if ip.strip()}
    allowed_ips.add(bind_ip)
    use_sudo = args.use_sudo
    drop_user = args.user if args.user != "" else None
    drop_group = args.group if args.group != "" else None
    auto_discovery = args.auto_discovery
    discovery_interval = args.discovery_interval
    max_workers = args.max_workers

    logging.info("Configuration: wg_interface=%s, bind_ip=%s, port=%d, allowed_ips=%s, use_sudo=%s, auto_discovery=%s, discovery_interval=%d, cache_freshness=%d, cache_wait_timeout=%d, max_workers=%d, user=%s, group=%s",
                 wg_interface, bind_ip, port, allowed_ips, use_sudo, auto_discovery,
                 discovery_interval, args.cache_freshness, args.cache_wait_timeout, max_workers, drop_user, drop_group)
    run_server(bind_ip, port, wg_interface, allowed_ips, use_sudo, drop_user, drop_group,
               auto_discovery, discovery_interval, max_workers)


if __name__ == "__main__":
    main()
