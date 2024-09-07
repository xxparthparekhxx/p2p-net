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
- **NAT Traversal:** Advanced techniques for establishing connections across different network environments.

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

The **Introduction Server** plays a pivotal role in enabling NAT traversal and initial peer discovery. Although the network is largely decentralized, the Introduction Server acts as a bootstrap node for new peers and assists in punching holes through NATs. It:
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
2. **Direct Communication:** Once discovered, peers establish a direct connection, bypassing the Introduction Server.

### **NAT Traversal**

NAT traversal is achieved through a combination of:
- **Hole Punching:** Leveraging the Introduction Server to facilitate direct connections between peers behind NATs.
- **UPnP and STUN:** Optional support for Universal Plug and Play (UPnP) and Session Traversal Utilities for NAT (STUN) for more robust NAT traversal.

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

- **Encryption:** All communication between peers is encrypted using industry-standard cryptographic algorithms.
- **Authentication:** Peers are authenticated using public key cryptography.
- **Resilience:** The protocol is designed to handle malicious nodes by incorporating redundancy and cryptographic verification.

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

To start a node:

```bash
python main.py --start-node
```

To query the DHT:

```bash
python main.py --query <domain_name>
```

## **Contributing**

We welcome contributions from the community! Please read our [contributing guidelines](CONTRIBUTING.md) for more information on how to get involved.

## **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

