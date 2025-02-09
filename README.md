# wg-discovery

`wg-discovery` is a lightweight tool/service for WireGuard that automates the
discovery and management of peer-to-peer endpoints. It runs as an HTTP
service, providing a JSON API to:

- Expose a list of reachable peers via a GET request over the WireGuard
  interface.
- Allows the peer to dynamically configure their endpoint information from
  remote peers in the network.

`wg-discovery` is designed to work in decentralized WireGuard setups — helping
peers to detect one another’s direct connection details automatically without
relying on central servers to forward actual traffic. Only the connection
endpoint details are provided to peers through other nodes in the WireGuard
network. For this to work over NAT networks (including NAT vs NAT), at least one of
the nodes within the network must have a public IP and this discovery service
available.

## NAT Hole Punching

NAT hole punching is a technique that allows two devices behind separate NATs
to establish direct communication. This usually works even if both systems are
behind a NAT, as long as at least one device has a way to discover and share
its external address. However, if multiple devices behind the same NAT use the
same WireGuard port, only one of them will be reachable at a time. To ensure
proper connectivity for multiple devices behind the same NAT, each system
should use a unique WireGuard port number.

For NAT hole punching to work effectively, at least one peer in the network
must have a public IP address and be running this WireGuard discovery service.
This peer acts as a relay for endpoint information, helping nodes behind NATs
discover each other’s external addresses and establish direct communication.
Without a publicly reachable discovery service, peers behind NATs would have
no way to learn the necessary connection details.

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
