"""NAT fallback relay: the protocol constants shared by the introduction
server and the peers.

A peer the introduction server cannot dial back keeps one persistent
"channel" connection to the server. Another peer that cannot reach it
directly opens a one-shot "request" connection and asks the server to
forward one framed DHT message over that channel; the server hands the
reply back. The relay never looks inside the messages, and a peer
verifies every record by its Ed25519 signature as usual, so the relay is
not trusted for content. Both connections are made to the introduction
server's own port and open with one unframed JSON object (like a join);
everything after that is length-prefixed frames (see kademlia_dht.py).

Channel:
  peer -> server   {"type": "relay_register", "virtual_ip", "token"}
  server -> peer   frame {"type": "relay_registered"}, or {"type": "error"}
  then JSON frames both ways:
  server -> peer   {"type": "relayed", "id", "from", "payload": base64}
  peer -> server   {"type": "relay_reply", "id", "payload": base64}, or
                   {"type": "relay_reply", "id", "error"}
  peer -> server   {"type": "ping"}      server -> peer  {"type": "pong"}

Request:
  peer -> server   {"type": "relay", "from", "token", "to"}
  server -> peer   frame {"type": "relay_ready"}, or {"type": "relay_failed"}
  peer -> server   frame: the DHT request itself (at most 1 MB)
  server -> peer   frame {"type": "relay_reply", "payload": base64}, or
                   {"type": "relay_failed", "error"}

`virtual_ip` and `token` are the values from the join reply: the token is
what stops another peer from registering a channel as, or relaying as, a
peer it is not.
"""

from kademlia_dht import MAX_MESSAGE_SIZE

# A relayed message is an ordinary framed DHT message and obeys its 1 MB cap,
# in both directions. The JSON frames that carry it base64-encode it (4/3 the
# size), so they get a bigger frame cap.
MAX_RELAYED_MESSAGE_SIZE = MAX_MESSAGE_SIZE
MAX_RELAY_FRAME_SIZE = 2 * MAX_MESSAGE_SIZE

# The channel is quiet between requests, so the peer pings on it to keep a
# NAT's idle-connection mapping alive and to notice a dead server; either
# side gives up on a channel that has been silent for RELAY_IDLE_TIMEOUT
# (a few missed pings).
RELAY_PING_INTERVAL = 25
RELAY_IDLE_TIMEOUT = 90

# How long the server waits for the relayed peer's reply. The sender waits
# that, plus a READ_TIMEOUT of slack, for the server's answer.
RELAY_TIMEOUT = 15
