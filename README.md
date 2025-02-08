# wg-discovery

`wg-discovery` is a lightweight, peer-to-peer tool for WireGuard that automates 
the discovery and management of peer endpoints. It runs as an HTTP service, 
providing a JSON API to:

- **Expose Current Endpoints:**  
  Retrieve a list of active peer endpoints via a GET request.

- **Dynamically Update Endpoints:**  
  Allow peers to update their endpoint information via a POST request.

- **Security:**  
  Enforce source IP filtering and optionally drop privileges after binding the 
  listening socket.

wg-discovery is designed to work in decentralized WireGuard setups—helping peers 
update one another’s connection details automatically without relying on a central server.

## Sudo Access

If you run the service as a non-root user, you'll need to allow that user to 
execute the `wg` command via sudo without a password prompt. For example, to 
allow the user `bob` to run the `wg` command located at `/usr/bin/wg`, add the 
following line to your sudoers configuration (using visudo):

```sudoers
bob ALL=(root) NOPASSWD: /usr/bin/wg
```

Replace `bob` with your username and adjust the path to the wg binary if necessary.
