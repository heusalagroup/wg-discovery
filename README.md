# wg-discovery

`wg-discovery` is a lightweight tool/service for WireGuard that automates the 
discovery and management of peer-to-peer endpoints. It runs as an HTTP 
service, providing a JSON API to:

- Expose a list of reachable peers via a GET request over the WireGuard 
  interface.

- Allows the peer to dynamically configure their endpoint information from 
  remote peers in the network

`wg-discovery` is designed to work in decentralized WireGuard setups — helping 
peers to detect one another’s direct connection details automatically without 
relying on a central servers to forward traffic. Only connection end point 
details are provided to peers through other nodes in the WireGuard network.

It is intended to be run on the internal WireGuard network and secured by 
WireGuard's own security layers. It is **NOT** intended to be exposed as a 
publicly available HTTP service.

## Sudo Access

If you run the service as a non-root user, you'll need to allow that user to 
execute the `wg` command via sudo without a password prompt. For example, to 
allow the user `bob` to run the `wg` command located at `/usr/bin/wg`, add the 
following line to your sudoers configuration (using visudo):

```sudoers
bob ALL=(root) NOPASSWD: /usr/bin/wg
```

Replace `bob` with your username and adjust the path to the wg binary if necessary.
