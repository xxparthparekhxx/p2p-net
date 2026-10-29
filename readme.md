# **Peer-to-Peer Network Protocol - Alpha**

This repository contains the implementation of a novel peer-to-peer (P2P) network protocol designed to facilitate the decentralized connection of peers, provide domain name resolution, and enable efficient resource discovery within a distributed network. The protocol supports both intranet and internet communication, with a focus on NAT traversal, scalability, and security.

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
- **NAT Traversal:** Planned — advanced techniques for establishing connections across different network environments are on the roadmap (see [NAT Traversal](#nat-traversal)).

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

The **Introduction Server** acts as a bootstrap node for new peers. NAT hole punching through it is planned but not yet implemented. It:
- Stores information about peers temporarily.
- Facilitates the initial connection setup between two peers.
- Helps peers discover each other by providing a rendezvous point.

## **Protocol Workflow**

### **Domain Name Resolution**

The protocol provides a decentralized domain name resolution system. The workflow involves:
1. **Querying the DHT:** A peer queries the DHT to resolve a domain name to an IP address or other resource.
2. **Response:** The DHT responds with the necessary data, which the querying peer uses to establish a direct connection.

### **Peer Connection**

Peer connections follow this process:
1. **Peer Discovery:** Peers discover each other using the Kademlia DHT and Introduction Server.
2. **Direct Communication:** Planned — once discovered, peers are intended to establish a direct connection, bypassing the Introduction Server.

### **NAT Traversal**

NAT traversal is planned but not yet implemented. The Introduction Server exists as a bootstrap rendezvous point; the following techniques are on the roadmap:
- **Hole Punching:** Planned — leverage the Introduction Server to facilitate direct connections between peers behind NATs.
- **UPnP and STUN:** Planned — optional support for Universal Plug and Play (UPnP) and Session Traversal Utilities for NAT (STUN) for more robust NAT traversal.

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
- **Authentication:** Implemented — STORE records are signed with the storing
  node's Ed25519 long-term key, and peers verify the signature before storing
  anything. A STORE record is exactly five space-separated tokens:

  `STOR <key> <seq> <base64 value> <base64 owner public key> <base64 signature>`

  The value and both cryptographic fields are base64-encoded so values of any
  bytes (including leading/trailing spaces and the empty string) round-trip
  exactly. The signature covers a domain-separated message:

  `p2p-net/STORE/v1\0<key>\0<seq>\0<value_bytes>`

  where `<seq>` is an unsigned 64-bit sequence number (`time.time_ns()`)
  written by the owner when it calls store(). Values must be UTF-8 text. A
  node stores `(owner public key, seq, value, signature)` per name. Names are
  owned on trust-on-first-use per node:
  the first valid signed STORE for a name on a node that has never seen it
  binds it to the signer's public key there. A later STORE for that name is
  accepted only from the same owner and only with a strictly greater seq
  (an equal seq with the identical value is an idempotent no-op); anything
  else is rejected with REJECTED. This prevents replaying an old signed STORE
  to roll a record back. Records are self-verifying: FIND_VALUE returns the
  whole signed record (key, seq, value, owner key and signature), and a
  lookup re-checks the signature on every reply, ignores any that fail and
  returns the verified record with the highest seq (pass `expected_owner` to
  accept only one owner's key). A node can refuse to answer or serve an older
  signed copy, but it cannot forge a record under someone else's key. There
  is no global registry: ownership is independent on each node,
  whoever stores a name first on that node becomes its owner there. Replication
  carries the original owner's signature and seq unchanged; a node never
  re-signs someone else's record with its own key. Because names are bound to
  that key, a node keeps its Ed25519 signing key across restarts in
  `~/.p2p-net/node_<port>.key` (override with the `key_path` argument or the
  `P2P_NET_KEY_DIR` directory). The file is created with mode 0600; a node
  that loses it can no longer update the names it registered.
- **Resilience:** Planned — the protocol is designed to handle malicious nodes by incorporating redundancy and cryptographic verification.

## **Future Work**

Planned enhancements include:
- **Browser Integration:** Developing a custom browser to interact with this P2P network.
- **Clear Web Access:** Enabling access to traditional websites via this protocol.
- **Enhanced NAT Traversal:** Further improvements to NAT traversal techniques.
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

To start a Introduction server:

```bash
python introduction_server.py
```

To start a Node (currently it is initalizing 10 nodes and connecting each other and registering 2 domians and it checks if it is able to retirve the vIP address of the node):

```bash
python p2p_node.py
```

## **Contributing**

We welcome contributions from the community! Please read our [contributing guidelines](CONTRIBUTING.md) for more information on how to get involved.

## **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

