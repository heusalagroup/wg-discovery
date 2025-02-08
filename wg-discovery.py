#!/usr/bin/env python3
"""
Simple dynamic WireGuard endpoint service.

- Exposes current endpoint data via GET /v1/endpoints.
- Allows updating a peer's endpoint via POST /v1/update.
- Uses source IP filtering to restrict access (if provided).
- All configuration is provided via command‑line arguments.
- Automatically determines the local IP of the selected WireGuard interface
  if --bind-ip is not provided.
- Automatically adds the bind IP to the allowed source IPs.
- Returns error messages in responses when errors occur.
- Optionally drops privileges to a specified user and group.

Intended to run as a systemd service on Linux (adaptable to macOS via launchd).

Usage example:
    sudo python3 wg_endpoint_service.py --wg-interface wg0 --port 51820 \
      --allowed-ips 10.220.0.19,10.220.0.25 --use-sudo --user nobody --group nogroup
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
                    0x8915,
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


class WGEndpointHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, wg_interface, allowed_source_ips, use_sudo, **kwargs):
        self.wg_interface = wg_interface
        self.allowed_source_ips = allowed_source_ips
        self.use_sudo = use_sudo
        super().__init__(*args, **kwargs)

    def _send_response(self, code, message, content_type="text/plain"):
        """
        Send an HTTP response with the given status code, message, and content type.
        The message can be a str or bytes.
        """
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        if isinstance(message, str):
            message = message.encode("utf-8")
        self.wfile.write(message)

    def _check_source_ip(self):
        # If no allowed source IPs are provided, allow all.
        if not self.allowed_source_ips:
            return True

        client_ip = self.client_address[0]
        if client_ip not in self.allowed_source_ips:
            logging.warning("Rejected connection from unauthorized IP: %s", client_ip)
            self._send_response(403, f"Forbidden: IP {client_ip} is not allowed.")
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
                self._send_response(200, result.stdout)
            except subprocess.CalledProcessError as e:
                error_message = f"Internal Server Error: {e.stderr}"
                logging.error("Error running wg show: %s", e.stderr)
                self._send_response(500, error_message)
        else:
            self._send_response(404, "Not Found")

    def do_POST(self):
        if not self._check_source_ip():
            return

        parsed = urlparse(self.path)
        if parsed.path == "/v1/update":
            content_length = int(self.headers.get("Content-Length", 0))
            payload = self.rfile.read(content_length)
            try:
                data = json.loads(payload)
                peer_key = data.get("peer")
                new_endpoint = data.get("endpoint")
                if not peer_key or not new_endpoint:
                    raise ValueError("Missing peer or endpoint")
            except Exception as e:
                error_message = f"Bad Request: Invalid JSON - {str(e)}"
                logging.error("Invalid JSON payload: %s", e)
                self._send_response(400, error_message)
                return

            try:
                cmd = ["wg", "set", self.wg_interface, "peer", peer_key, "endpoint", new_endpoint]
                if self.use_sudo:
                    cmd = ["sudo"] + cmd
                logging.info("Running command: %s", " ".join(cmd))
                subprocess.run(cmd, check=True)
                self._send_response(200, "Peer endpoint updated successfully")
            except subprocess.CalledProcessError as e:
                error_message = f"Internal Server Error: Unable to update endpoint - {e.stderr}"
                logging.error("Error updating endpoint: %s", e)
                self._send_response(500, error_message)
        else:
            self._send_response(404, "Not Found")

    def log_message(self, format, *args):
        logging.info("%s - %s", self.address_string(), format % args)


def run_server(bind_ip, port, wg_interface, allowed_source_ips, use_sudo, drop_user, drop_group):
    handler_class = partial(WGEndpointHandler,
                            wg_interface=wg_interface,
                            allowed_source_ips=allowed_source_ips,
                            use_sudo=use_sudo)
    with socketserver.TCPServer((bind_ip, port), handler_class) as httpd:
        logging.info("Starting WG endpoint service on http://%s:%d/", bind_ip, port)
        if drop_user:
            try:
                drop_privileges(drop_user, drop_group)
            except Exception as e:
                logging.error("Failed to drop privileges: %s", e)
                sys.exit(1)
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
    allowed_source_ips = {ip.strip() for ip in args.allowed_source_ips.split(',') if ip.strip()}
    allowed_source_ips.add(bind_ip)
    use_sudo = args.use_sudo
    drop_user = args.user if args.user != "" else None
    drop_group = args.group if args.group != "" else None

    logging.info("Configuration: wg_interface=%s, bind_ip=%s, port=%d, allowed_source_ips=%s, use_sudo=%s, user=%s, group=%s",
                 wg_interface, bind_ip, port, allowed_source_ips, use_sudo, drop_user, drop_group)
    run_server(bind_ip, port, wg_interface, allowed_source_ips, use_sudo, drop_user, drop_group)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
    main()
