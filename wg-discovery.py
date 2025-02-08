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
- Optionally runs an auto‑update thread that detects discovery peers by looping
  through all peers from 'wg show <interface> endpoints', then periodically “pings”
  each peer via HTTP. If a peer is inactive, the service queries discovery peers
  for updated endpoint information and updates the local configuration.

Intended to run as a systemd service on Linux (adaptable to macOS via launchd).

Usage example:
    sudo python3 wg_endpoint_service.py --wg-interface wg0 --port 51820 \
      --allowed-ips 10.220.0.19,10.220.0.25 --use-sudo --user nobody --group nogroup \
      --auto-update --update-interval 60
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


def parse_wg_endpoints(output):
    """
    Parse the output from 'wg show <interface> endpoints' into a JSON object.

    Expected sample output (tab-separated):

        1234567890+abcdedfgh+23AdJgYev355laseg88g34=	(none)
        P92pvrbwGG12512312sxsf141tqad14raerafeag144=	1.2.3.4:51820
        jkgashlkh1l4haf134gat235gstq5gwrtq35twtw54w=	5.6.7.8:51820

    Returns a dictionary in the form:
      {
          "1234567890+abcdedfgh+23AdJgYev355laseg88g34=": null,
          "P92pvrbwGG12512312sxsf141tqad14raerafeag144=": "1.2.3.4:51820",
          "jkgashlkh1l4haf134gat235gstq5gwrtq35twtw54w": "5.6.7.8:51820"
      }
    """
    endpoints = {}
    for line in output.splitlines():
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
        # If no allowed IPs are provided, allow all.
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
        if parsed.path == "/v1/endpoints":
            try:
                cmd = ["wg", "show", self.wg_interface, "endpoints"]
                if self.use_sudo:
                    cmd = ["sudo"] + cmd
                result = subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                parsed_output = parse_wg_endpoints(result.stdout)
                self._send_json_response(200, parsed_output)
            except subprocess.CalledProcessError as e:
                error_message = {"error": "Internal Server Error", "message": e.stderr}
                logging.error("Error running wg show: %s", e.stderr)
                self._send_json_response(500, error_message)
        else:
            self._send_json_response(404, {"error": "Not Found"})

    def log_message(self, format, *args):
        logging.info("%s - %s", self.address_string(), format % args)


def auto_update_loop(wg_interface, local_port, use_sudo, update_interval):
    """
    Periodically check local peers for activity and update endpoints for inactive peers.

    The auto-update loop works as follows:

    1. It retrieves local endpoints using 'wg show <interface> endpoints'.
    2. It then automatically detects discovery peers by iterating through all peers
       that have a non-null endpoint. For each, it sends an HTTP GET request to
       http://<peer_ip>:<local_port>/v1/endpoints. Peers that respond successfully
       are considered discovery peers.
    3. Next, for each local peer, it attempts to "ping" the peer via HTTP GET.
       If a peer is unreachable, it loops through the discovered discovery peers
       and queries each for updated endpoint information for that inactive peer.
    4. If a discovery peer returns a new, non-null endpoint for the inactive peer,
       the service updates the local WireGuard configuration accordingly.
    """
    while True:
        logging.info("Auto-update loop starting iteration...")
        try:
            cmd = ["wg", "show", wg_interface, "endpoints"]
            if use_sudo:
                cmd = ["sudo"] + cmd
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            local_endpoints = parse_wg_endpoints(result.stdout)
        except Exception as e:
            logging.error("Failed to get local endpoints: %s", e)
            time.sleep(update_interval)
            continue

        # Automatically detect discovery peers from the local endpoints.
        discovery_peers = {}
        for peer_key, endpoint in local_endpoints.items():
            if not endpoint:
                continue
            try:
                host, _ = endpoint.split(':')
            except Exception as e:
                logging.error("Invalid endpoint format for peer %s: %s", peer_key, endpoint)
                continue
            url = f"http://{host}:{local_port}/v1/endpoints"
            try:
                with urllib.request.urlopen(url, timeout=5) as response:
                    if response.status == 200:
                        discovery_peers[peer_key] = endpoint
                        logging.info("Discovery peer detected: %s at %s", peer_key, endpoint)
            except Exception as e:
                logging.warning("Peer %s at %s is not a discovery node: %s", peer_key, endpoint, e)

        # For each peer, if it's inactive, try to update its endpoint.
        for peer_key, endpoint in local_endpoints.items():
            if not endpoint:
                continue
            try:
                host, _ = endpoint.split(':')
            except Exception as e:
                logging.error("Invalid endpoint format for peer %s: %s", peer_key, endpoint)
                continue
            url = f"http://{host}:{local_port}/v1/endpoints"
            try:
                with urllib.request.urlopen(url, timeout=5) as response:
                    if response.status == 200:
                        logging.info("Peer %s at %s is active", peer_key, endpoint)
                        continue  # Active, no update needed.
            except Exception as e:
                logging.warning("Peer %s at %s is inactive: %s", peer_key, endpoint, e)
            # If inactive, query discovery peers for an updated endpoint.
            new_endpoint = None
            for disc_key, disc_endpoint in discovery_peers.items():
                try:
                    d_host, _ = disc_endpoint.split(':')
                    disc_url = f"http://{d_host}:{local_port}/v1/endpoints"
                    with urllib.request.urlopen(disc_url, timeout=5) as disc_response:
                        if disc_response.status == 200:
                            disc_data = json.loads(disc_response.read().decode("utf-8"))
                            if peer_key in disc_data and disc_data[peer_key]:
                                new_endpoint = disc_data[peer_key]
                                logging.info("Found updated endpoint for peer %s from discovery node %s: %s", peer_key, disc_key, new_endpoint)
                                break
                except Exception as e:
                    logging.warning("Error querying discovery node %s: %s", disc_key, e)
            if new_endpoint and new_endpoint != endpoint:
                try:
                    cmd = ["wg", "set", wg_interface, "peer", peer_key, "endpoint", new_endpoint]
                    if use_sudo:
                        cmd = ["sudo"] + cmd
                    subprocess.run(cmd, check=True)
                    logging.info("Updated peer %s endpoint to %s", peer_key, new_endpoint)
                except Exception as e:
                    logging.error("Failed to update peer %s: %s", peer_key, e)
        time.sleep(update_interval)


def run_server(bind_ip, port, wg_interface, allowed_ips, use_sudo, drop_user, drop_group,
               auto_update, update_interval):
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
        if auto_update:
            thread = threading.Thread(target=auto_update_loop, args=(wg_interface, port, use_sudo, update_interval))
            thread.daemon = True
            thread.start()
            logging.info("Auto-update thread started.")
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
    parser.add_argument('--auto-update', action='store_true', help='Enable auto-update of peer endpoints (default: disabled)')
    parser.add_argument('--update-interval', type=int, default=60,
                        help='Interval (in seconds) between auto-update checks (default: 60)')
    return parser.parse_args()


def main():
    args = parse_args()
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
    auto_update = args.auto_update
    update_interval = args.update_interval

    logging.info("Configuration: wg_interface=%s, bind_ip=%s, port=%d, allowed_ips=%s, use_sudo=%s, auto_update=%s, update_interval=%d, user=%s, group=%s",
                 wg_interface, bind_ip, port, allowed_ips, use_sudo, auto_update, update_interval, drop_user, drop_group)
    run_server(bind_ip, port, wg_interface, allowed_ips, use_sudo, drop_user, drop_group,
               auto_update, update_interval)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
    main()
