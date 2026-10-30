# **Peer-to-Peer Network Protocol - Alpha**

This repository contains the implementation of a novel peer-to-peer (P2P) network protocol designed to facilitate the decentralized connection of peers, provide domain name resolution, and enable efficient resource discovery within a distributed network. The protocol is meant to work on both intranets and the internet; for peers that cannot accept inbound connections (for example behind a NAT) it has a relay through the introduction server, described under [NAT Traversal](#nat-traversal).

## **Table of Contents**
- [**Peer-to-Peer Network Protocol - Alpha**](#peer-to-peer-network-protocol---alpha)
  - [**Table of Contents**](#table-of-contents)
  - [**Introduction**](#introduction)
  - [**Architecture Overview**](#architecture-overview)
    - [**P2PNode**](#p2pnode)
    - [**Kademlia DHT**](#kademlia-dht)
    - [**Introduction Server**](#introduction-server)
  - [**Protocol Workflow**](#protocol-workflow)
    - [**Domain Name Resolution**](#domain-name-resolution)
    - [**Peer Connection**](#peer-connection)
    - [**NAT Traversal**](#nat-traversal)
  - [**Implementation Details**](#implementation-details)
    - [**Node Communication**](#node-communication)
    - [**Data Structures**](#data-structures)
    - [**Security Considerations**](#security-considerations)
  - [**Future Work**](#future-work)
  - [**Getting Started**](#getting-started)
    - [**Installation**](#installation)
    - [**Usage**](#usage)
  - [**Contributing**](#contributing)
  - [**License**](#license)

## **Introduction**

This protocol is designed to serve as the foundational layer for a distributed network, enabling the connection of peers and the discovery of resources such as domain names and services. Unlike traditional DNS, this protocol offers a decentralized approach where domains are only accessible via this specific network. Once the necessary data is retrieved (e.g., server IP), direct communication between client and server is established, offloading data traffic from the core network.

Key Features:
- **Decentralized Domain Name Resolution:** A P2P approach to DNS that ensures scalability and robustness.
- **Direct Peer Communication:** Reduces network load by facilitating direct client-server interactions.
- **NAT Traversal (partial):** the introduction server reports each peer's observed address, checks whether the peer accepts inbound connections, and relays DHT messages to peers that do not. Optional UPnP port mapping. TCP hole punching is not implemented (see [NAT Traversal](#nat-traversal)).

## **Architecture Overview**

### **P2PNode**

The `P2PNode` is the fundamental building block of the network, representing an individual peer participating in the network. Each node is responsible for:
- Maintaining a list of known peers.
- Participating in the Kademlia Distributed Hash Table (DHT) for resource discovery.
- Handling incoming and outgoing connections with other peers.

### **Kademlia DHT**

The protocol leverages the **Kademlia Distributed Hash Table (DHT)** to enable efficient resource discovery. Kademlia offers several advantages:
- **Scalability:** Efficiently handles large numbers of nodes and resources.
- **Fault Tolerance:** Redundancy and replication across the network.
- **Low Latency:** Optimized lookups using XOR distance metrics.

Kademlia operates by assigning unique identifiers (node IDs) to each peer and resource in the network. The DHT is used to map these IDs to network locations, enabling peers to discover resources and other peers.

### **Introduction Server**

The **Introduction Server** acts as a bootstrap node for new peers. It:
- Stores information about peers temporarily.
- Facilitates the initial connection setup between two peers.
- Helps peers discover each other by providing a rendezvous point.
- Tells each joining peer the address it connected from, and checks whether the peer accepts inbound connections.
- Relays DHT messages to peers that do not (see [NAT Traversal](#nat-traversal)). It does not interpret the messages it relays.

## **Protocol Workflow**

### **Domain Name Resolution**

The protocol provides a decentralized domain name resolution system. The workflow involves:
1. **Querying the DHT:** A peer queries the DHT to resolve a domain name to an IP address or other resource.
2. **Response:** The DHT responds with the necessary data, which the querying peer uses to establish a direct connection.

### **Peer Connection**

Peer connections follow this process:
1. **Peer Discovery:** Peers discover each other using the Kademlia DHT and Introduction Server.
2. **Direct Communication:** DHT requests go from node to node over TCP, without the Introduction Server. When a contact cannot be dialed they go through the Introduction Server's relay instead. The only traffic between peers is DHT messages; a general-purpose direct channel for application data is not built.

### **NAT Traversal**

A peer behind a NAT that refuses inbound connections can still make outgoing connections, but other peers cannot dial it. The code handles that in four parts; the table at the end of the section says what is and is not done.

1. **Reflexive address discovery.** When a peer joins, the Introduction Server records the address it sees the join connection come from and returns it as `observed_address` (`{"ip", "port"}`); `P2PNode.observed_address` holds it and `join_network` prints it. This is the address of the join connection, which a NAT usually gives a different external port than the listening port. It is only reported: the node still advertises the `ip` and `port` it was constructed with, and its node id is derived from them.
2. **Reachability check.** After a join the server dials the peer's advertised listening address (bounded by `CONNECT_TIMEOUT`) and returns `directly_reachable`. It only dials the IP the peer connected from, so it cannot be used to make the server connect to arbitrary hosts; a peer that advertises a different IP (for example a LAN address behind a NAT) is reported as not reachable without any connection attempt. The flag is kept with the peer, handed out to later joiners in `nearby_peers` (as `reachable`, together with the peer's `virtual_ip`), and passed along in FIND_NODE / FIND_VALUE contact lists as the optional fields `reachable` and `virtual_ip`.
3. **Relay.** The join reply carries a secret `relay_token` for the joining peer. A peer that was found not reachable keeps one persistent "channel" connection open to the Introduction Server (`relay_register`, with its virtual ip and token). When a node needs to send a DHT request to a contact, `KademliaNode._exchange` dials it directly; if that fails (or the contact is already known to be unreachable, in which case the relay is tried first) and the contact's virtual ip is known, the request is sent through the server instead: the sender opens a one-shot `relay` connection naming the destination, the server forwards the framed message over the destination's channel, and the destination's reply comes back the same way. A reachable node opens no channel but uses the relay to reach unreachable contacts; an unreachable node's own outgoing connections stay direct. Nodes behind NATs can reach each other this way (relay to relay). The wire format is described at the top of `relay.py`.
   - **Only between joined peers.** Registering a channel and sending a relay request both need a joined peer's virtual ip and its `relay_token`; the destination must have joined too. (Virtual ips are sequential and public, so the ip alone proves nothing.)
   - **Same size cap as direct messages.** A relayed request or reply over `MAX_MESSAGE_SIZE` (1 MB) is refused by the server and by the peers; the base64 JSON frames that carry it get a 2 MB frame cap.
   - **Limits and timeouts** (module constants in `introduction_server.py` and `relay.py`):

     | Constant | Value | Effect |
     | --- | --- | --- |
     | `RELAY_RATE_LIMIT` / `RELAY_RATE_WINDOW` | 50 per 1 s | Relay requests per sending peer (refused ones count). |
     | `MAX_PENDING_RELAYS_PER_SENDER` | 8 | Relays one peer may have waiting for a reply. |
     | `MAX_PENDING_RELAYS_PER_PEER` | 16 | Relays that may be waiting on one destination. |
     | `MAX_PENDING_RELAYS` | 64 | Relays waiting on replies, in total. |
     | `RELAY_TIMEOUT` | 15 s | How long the server waits for the destination's reply. |
     | `RELAY_WRITE_TIMEOUT` | 10 s | A destination that does not read its channel is dropped. |
     | `RELAY_PING_INTERVAL` / `RELAY_IDLE_TIMEOUT` | 25 s / 90 s | A channel is pinged to keep a NAT mapping alive; a silent one is closed by either side. |
     | `RELAY_RECONNECT_MIN` / `RELAY_RECONNECT_MAX` | 1 s / 30 s | A dropped channel is reopened with a doubling delay. |

   - **Records are still verified end to end.** The relay forwards the same framed messages a direct connection would carry and never interprets them. A record in a relayed reply is checked against its Ed25519 signature (and the owner policy above) exactly like a direct one, so the relay does not have to be trusted for content: it can drop, delay or serve an older signed copy of a record, but it cannot forge one.
   - **Not private.** Relayed traffic is plain TCP like everything else here (encryption is not built), so the server sees every relayed message, and anyone on the path to the server can read a peer's `relay_token` and use it.
   - **Metadata is not authenticated.** `reachable` and `virtual_ip` in a contact list come from the peer that sent it. A lying peer can point a contact at another peer's virtual ip, so requests meant for the contact go to that peer; it can waste relay capacity but not forge records.
4. **UPnP (optional).** If the `miniupnpc` Python package is importable (`pip install miniupnpc`; it is not in `requirements.txt`), `P2PNode.start()` asks the router to forward the node's listening TCP port to this host and `stop()` (which `run()` calls on exit) removes the mapping. A missing package is ignored silently; a router without UPnP, or one that refuses or does not answer, is logged and ignored. The router calls run in a worker thread with a 10 s timeout. A node listening on loopback does not try, and `P2PNode(..., upnp=False)` turns it off. The mapping has no lease time, so a node that is killed without stopping leaves it on the router. The node still advertises the `ip` it was constructed with, and the reachability check only accepts the IP the peer connected from, so UPnP alone does not make a node constructed with a LAN address count as reachable: that node is still reported as not reachable and keeps a relay channel.

| Part | Status |
| --- | --- |
| Reflexive address discovery | Implemented. Reported by the Introduction Server, not used for what a node advertises. |
| Reachability check | Implemented (dial-back to the peer's own IP only). |
| Relay through the Introduction Server | Implemented for DHT messages. |
| UPnP port mapping | Implemented, optional. Tested only against a fake `miniupnpc`. |
| TCP hole punching | Not implemented. |
| STUN | Not implemented; the observed address comes only from the Introduction Server. |

**How it was tested.** Only in simulation, on one machine. No real NAT, router or `miniupnpc` was used. A peer "behind a NAT" in the tests is a node that advertises a port nothing listens on (or never starts listening), so the server's dial-back and every direct dial to it fail; the Introduction Server, the relay and the nodes are real code talking over loopback TCP. UPnP is tested against a stand-in `miniupnpc` module. Behaviour with real NAT types, a real router, or an Introduction Server across the internet has not been checked. TCP hole punching is left out because it cannot be tested here without a real NAT, and a test on one machine would not show whether it works against one.

## **Implementation Details**

### **Node Communication**

- **Protocol:** Communication between nodes is handled using a lightweight, custom protocol optimized for P2P interactions.
- **Message Types:** Nodes exchange various message types, including:
  - **Ping/Pong:** For maintaining connectivity.
  - **Store/Find:** For DHT operations.
  - **Request/Response:** For resource discovery and data retrieval.

### **Data Structures**

- **Kademlia Routing Table:** Maintains a list of known peers, organized by XOR distance.
- **Resource Map:** A local cache of resolved domain names and resources.
- **Peer List:** A list of connected peers, updated dynamically.

### **Security Considerations**

- **Encryption:** Planned — all communication between peers is intended to be encrypted using industry-standard cryptographic algorithms. The introduction server no longer distributes a network key in plaintext; peers exchange only join metadata, and record authenticity relies on the signed records below.
- **Authentication:** Implemented. STORE records are signed with the
  storing node's Ed25519 long-term key, and peers verify the signature before
  storing anything. A STORE record is exactly five space-separated tokens:

  `STOR <key> <seq> <base64 value> <base64 owner public key> <base64 signature>`

  The value and both cryptographic fields are base64-encoded so values of any
  bytes (including leading/trailing spaces and the empty string) round-trip
  exactly. The signature covers a domain-separated message:

  `p2p-net/STORE/v1\0<key>\0<seq>\0<value_bytes>`

  where `<seq>` is the owner's sequence number (`time.time_ns()` when it calls
  store()). seq must be an unsigned 64-bit integer (`0 <= seq < 2**64`); a
  STORE or a FIND_VALUE reply outside that range is rejected. Values must be
  UTF-8 text. A node stores `(owner public key, seq, value, signature)` per
  name, including a local copy of the names it stores itself when it is
  among the K closest nodes to the key.
- **Ownership:** trust-on-first-use, per node. The first valid signed STORE
  for a name on a node that has never seen it binds the name to the signer's
  public key there. A later STORE for that name is accepted only from the
  same owner and only with a strictly greater seq (an equal seq with the
  identical value is an idempotent no-op); anything else gets REJECTED. This
  prevents replaying an old signed STORE to roll a record back. There is no
  global registry: whoever stores a name first on a node owns it there.
  Replication carries the original owner's signature and seq unchanged; a
  node never re-signs someone else's record with its own key.
- **Read policy:** records are self-verifying. FIND_VALUE returns the whole
  signed record as JSON (`key`, `seq`, base64 `value`, base64 `owner`, base64
  `signature`), and a lookup re-checks the signature on every reply (and on
  the local copy), ignoring any that fail. A lookup queries the K closest
  nodes rather than stopping at the first answer, then:
  1. **Unpinned (first lookup of a name):** verified records are grouped by
     owner, and the owner served by the most distinct replicas wins. Replicas
     are counted by ip:port, so one endpoint reached under several contact
     ids counts once; the local copy counts as one. Within that owner, the
     highest seq wins. Ties are broken deterministically (lowest owner key),
     and a warning is logged whenever more than one owner is seen. A single
     malicious node serving its own record at seq `2**64-1` therefore loses
     to the owner that the honest replicas agree on.
  2. **Pinned (every later lookup):** `P2PNode.lookup_domain` pins the
     owner's public key the first time a name resolves, and from then on
     accepts only that owner's records (highest seq wins). Pins are saved
     next to the key file, named after it with an `.owners.json` extension
     (`node_9000.key` -> `node_9000.owners.json`; mode 0600, written
     crash-safely), so they survive restarts. `forget_owner(domain)` drops a
     pin; pass `owner=` to `lookup_domain` (or `expected_owner=` to
     `KademliaNode.find_value`) to pin a known key yourself.

  A node can refuse to answer or serve an older signed copy, but it cannot
  forge a record under someone else's key.
- **Keys:** a node keeps its Ed25519 signing key across restarts in
  `~/.p2p-net/node_<port>.key` (override with the `key_path` argument or the
  `P2P_NET_KEY_DIR` directory). A node on port 0 has no default key file (the
  port changes on every bind) and must be given `key_path`. New key files
  are written to a 0600 temp file in the same directory, fsynced and renamed
  into place, so a crash never leaves a torn key behind. A node that loses
  its key can no longer update the names it registered.
- **Limits and timeouts** (module constants in `kademlia_dht.py`):

  | Constant | Value | Effect |
  | --- | --- | --- |
  | `MAX_MESSAGE_SIZE` | 1 MB | Largest framed message accepted (4-byte length prefix). |
  | `MAX_VALUE_SIZE` | 512 KB | Largest STORE value (UTF-8 bytes); bigger ones are REJECTED. Replies carry the value base64-encoded, so every stored record fits in one reply. |
  | `MAX_RECORDS` | 10,000 | Records per node. A STORE for a new name past the cap is REJECTED; updates to stored names still work. |
  | `CONNECT_TIMEOUT` | 5 s | Every outgoing TCP connect; an unreachable contact can't stall a lookup round. |
  | `READ_TIMEOUT` | 10 s | Header and body of each framed message. |
  | `MAX_LOOKUP_QUERIES` | 4 × K = 80 | Most nodes one lookup queries. |

  Values and other peer-supplied text are logged with `repr()` and truncated,
  so escape sequences in a value never reach the operator's terminal.
- **Known limits:**
  - Contacts in FIND_NODE / FIND_VALUE replies are not authenticated: a node
    can claim any id and point at any address. A Sybil attacker that controls
    most of the K closest nodes for a name (distinct ip:port endpoints) can
    still win a node's first, unpinned lookup of that name, and that node
    then pins the attacker's key.
  - Records never expire. They live in memory until the node restarts, and
    a node that reaches `MAX_RECORDS` refuses new names until then. Record
    expiry and republishing are not built.
  - Ownership is per node (trust-on-first-use), not global; see above.
- **Resilience:** Planned — the protocol is designed to handle malicious nodes by incorporating redundancy and cryptographic verification.

## **Future Work**

Planned enhancements include:
- **Browser Integration:** Developing a custom browser to interact with this P2P network.
- **Clear Web Access:** Enabling access to traditional websites via this protocol.
- **Enhanced NAT Traversal:** TCP hole punching (coordinated through the Introduction Server) and STUN, neither of which exists yet, and testing against real NATs.
- **Demo Application:** A complete demo showcasing the protocol in action.

## **Getting Started**

### **Installation**

Clone the repository and install the necessary dependencies:

```bash
git clone https://github.com/yourusername/peer-to-peer-protocol.git
cd peer-to-peer-protocol
pip install -r requirements.txt
```

### **Usage**

To start the introduction server:

```bash
python introduction_server.py
```

It listens on `127.0.0.1:8888` by default, so it is reachable only from the
same machine. To accept peers from other machines, bind another address
explicitly, e.g. `python introduction_server.py --host 0.0.0.0`; `--port`
changes the port (`0` picks a free one).

To run the demo (with the introduction server running): it starts 10 nodes
on `127.0.0.1:9000-9009`, joins them through the introduction server at
`127.0.0.1:8888`, registers two domains and looks them up from another node.

```bash
python p2p_node.py
```

Node keys (and owner pins) go to `~/.p2p-net`; set `P2P_NET_KEY_DIR` to keep
them elsewhere, e.g. `P2P_NET_KEY_DIR=$(mktemp -d) python p2p_node.py`. If
the introduction server isn't reachable, `join_network` raises
`IntroductionServerUnreachable` and the demo prints the error and exits.

NAT traversal needs no setup beyond starting the introduction server where
every peer can reach it (see `--host` above). A node calls
`await node.start()` and `await node.join_network((host, port))` as usual;
the introduction server's reply tells it whether it is directly reachable,
and if it is not the node opens its relay channel by itself and uses the
relay to reach contacts it cannot dial. `P2PNode.observed_address`,
`directly_reachable` and `virtual_ip` hold what the server reported. For UPnP,
install the optional package (`pip install miniupnpc`); `P2PNode(ip, port,
upnp=False)` skips it.

Run the tests with `python -m pytest` (they need `pytest` and
`pytest-asyncio`, and keep all key files in temporary directories; they never
use a real router, even if `miniupnpc` is installed).

## **Contributing**

We welcome contributions from the community! Please read our [contributing guidelines](CONTRIBUTING.md) for more information on how to get involved.

## **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

