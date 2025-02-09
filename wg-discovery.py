#!/usr/bin/env python3
"""
Simple dynamic WireGuard endpoint service.

- Exposes current endpoint data via GET /v1/endpoints.
- Uses source IP filtering to restrict access (if provided).
- All configuration is provided via command‑line arguments.
- Automatically determines the local IP of the selected WireGuard interface
  if --bind-ip is not provided.
- Automatically adds the bind IP to the allowed source IPs.
- Returns responses and error messages in JSON format.
- Optionally drops privileges to a specified user and group.
- Optionally runs an auto‑discovery thread that:
    1. Retrieves each peer’s internal WireGuard IP (using 'wg show <interface> allowed-ips'),
    2. Pings each peer (via HTTP GET /v1/endpoints on that allowed IP),
    3. For peers that are inactive, queries active discovery peers (using their GET /v1/endpoints response)
       for updated endpoint information, and
    4. Updates the local configuration if a new endpoint is found.

Intended to run as a systemd service on Linux (adaptable to macOS via launchd).

Usage example:
    sudo python3 wg_endpoint_service.py --wg-interface wg0 --port 51820 \
      --allowed-ips 10.220.0.19,10.220.0.25 --use-sudo --user nobody --group nogroup \
      --auto-discovery --discovery-interval 60 --log-level DEBUG
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


class WGEndpointHandler(http.server.BaseHTTPRequestHandler):

    def __init__(self, *args, wg_interface, allowed_ips, use_sudo, **kwargs):
        self.wg_interface = wg_interface
        self.allowed_ips = allowed_ips
        self.use_sudo = use_sudo
        super().__init__(*args, **kwargs)

    def _send_json_response(self, code, data):
        """
        Send an HTTP response with the given status code and JSON data.
        """
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
            try:
                parsed_output = wg_show_endpoints(self.wg_interface, self.use_sudo)
                self._send_json_response(200, parsed_output)
            except subprocess.CalledProcessError as e:
                error_message = {"error": "Internal Server Error", "message": e.stderr}
                logging.error("Error running wg show endpoints: %s", e.stderr)
                self._send_json_response(500, error_message)
        else:
            self._send_json_response(404, {"error": "Not Found"})

    def log_message(self, format, *args):
        logging.info("%s - %s", self.address_string(), format % args)


def auto_discovery_loop(wg_interface, local_port, use_sudo, discovery_interval):
    """
    Periodically check local peers for activity and update endpoints for inactive peers.

    1. Retrieve the allowed IPs mapping using 'wg show <interface> allowed-ips' to obtain each peer's internal WG IP.
    2. For each peer, attempt to connect to its discovery service at:
         http://<allowed_ip>:<local_port>/v1/endpoints
       If the peer is unreachable, consider it inactive.
    3. For each inactive peer, loop through all active discovery peers (based on the allowed IPs mapping)
       and send an HTTP GET to their /v1/endpoints endpoint.
    4. If a discovery peer returns a non-null endpoint for the inactive peer, update the local configuration.
    """
    while True:
        logging.info("Auto-discovery loop starting iteration...")
        try:
            allowed_ips_map = wg_show_allowed_ips(wg_interface, use_sudo)
        except Exception as e:
            logging.error("Failed to get allowed IPs: %s", e)
            time.sleep(discovery_interval)
            continue

        inactive_peers = {}
        for peer_key, allowed_ip in allowed_ips_map.items():
            url = f"http://{allowed_ip}:{local_port}/v1/endpoints"
            try:
                with urllib.request.urlopen(url, timeout=5) as response:
                    if response.status == 200:
                        logging.info("Peer %s at %s is active", peer_key, allowed_ip)
                        continue
            except Exception as e:
                logging.debug("Peer %s at %s is inactive: %s", peer_key, allowed_ip, e)
                inactive_peers[peer_key] = allowed_ip

        # For each inactive peer, query discovery peers for an updated endpoint.
        for peer_key in inactive_peers:
            new_endpoint = None
            for disc_key, disc_allowed_ip in allowed_ips_map.items():
                if disc_key == peer_key:
                    continue
                disc_url = f"http://{disc_allowed_ip}:{local_port}/v1/endpoints"
                try:
                    with urllib.request.urlopen(disc_url, timeout=5) as disc_response:
                        if disc_response.status == 200:
                            disc_data = json.loads(disc_response.read().decode("utf-8"))
                            if peer_key in disc_data and disc_data[peer_key]:
                                new_endpoint = disc_data[peer_key]
                                logging.info("Found updated endpoint for peer %s from discovery node %s: %s", peer_key, disc_key, new_endpoint)
                                break
                except Exception as e:
                    logging.debug("Error querying discovery node %s: %s", disc_key, e)
            if new_endpoint and new_endpoint != inactive_peers[peer_key]:
                try:
                    wg_set_peer_endpoint(wg_interface, peer_key, new_endpoint, use_sudo)
                    logging.info("Updated peer %s endpoint to %s", peer_key, new_endpoint)
                except Exception as e:
                    logging.error("Failed to update peer %s: %s", peer_key, e)
        time.sleep(discovery_interval)


def run_server(bind_ip, port, wg_interface, allowed_ips, use_sudo, drop_user, drop_group,
               auto_discovery, discovery_interval):
    handler_class = partial(WGEndpointHandler,
                            wg_interface=wg_interface,
                            allowed_ips=allowed_ips,
                            use_sudo=use_sudo)
    with socketserver.TCPServer((bind_ip, port), handler_class) as httpd:
        logging.info("Starting WG endpoint service on http://%s:%d/", bind_ip, port)
        if drop_user:
            try:
                drop_privileges(drop_user, drop_group)
            except Exception as e:
                logging.error("Failed to drop privileges: %s", e)
                sys.exit(1)
        if auto_discovery:
            thread = threading.Thread(target=auto_discovery_loop, args=(wg_interface, port, use_sudo, discovery_interval))
            thread.daemon = True
            thread.start()
            logging.info("Auto-discovery thread started.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.info("Shutting down WG endpoint service")
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
                        help='Interval (in seconds) between auto-discovery checks (default: 60)')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level (default: INFO)')
    return parser.parse_args()


def main():
    args = parse_args()
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError("Invalid log level: %s" % args.log_level)
    logging.basicConfig(level=numeric_level, format='%(asctime)s %(levelname)s: %(message)s')

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

    logging.info("Configuration: wg_interface=%s, bind_ip=%s, port=%d, allowed_ips=%s, use_sudo=%s, auto_discovery=%s, discovery_interval=%d, user=%s, group=%s",
                 wg_interface, bind_ip, port, allowed_ips, use_sudo, auto_discovery, discovery_interval, drop_user, drop_group)
    run_server(bind_ip, port, wg_interface, allowed_ips, use_sudo, drop_user, drop_group,
               auto_discovery, discovery_interval)


if __name__ == "__main__":
    main()
