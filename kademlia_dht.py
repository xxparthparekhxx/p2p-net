import asyncio
import base64
import json
import hashlib
import os
import tempfile
import time
from typing import List, Tuple, Dict, NamedTuple, Optional, Union
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
from cryptography.exceptions import InvalidSignature

K = 20  # k-bucket size
ALPHA = 3  # alpha concurrent network calls
ID_BITS = 160  # SHA-1 hash size
# Most nodes a single lookup will query. Contacts in replies are unverified,
# so a malicious peer can keep handing out fresh, ever-closer ids; without a
# cap find_node / find_value would never terminate.
MAX_LOOKUP_QUERIES = 4 * K

# Every message on the wire is length-prefixed: a 4-byte big-endian length
# followed by exactly that many payload bytes. Replies are read with a loop
# (readexactly) so a full 20-node response can never overflow a fixed buffer.
# The declared length is capped so a peer cannot make us allocate an
# arbitrarily large buffer; larger messages are rejected.
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB

# Largest value a STORE may carry, in UTF-8 bytes. FIND_VALUE replies carry
# the value base64-encoded (4/3 the size) plus a few hundred bytes of JSON,
# so every record a node accepts also fits in one MAX_MESSAGE_SIZE reply.
MAX_VALUE_SIZE = 512 * 1024

# Most records one node keeps. A STORE for a new name beyond this is
# REJECTED; updates to names the node already holds still go through.
# (Records don't expire, so without a cap anyone could fill a node's memory.)
MAX_RECORDS = 10_000

# Read timeout (seconds) for the header and body of a single framed message.
# A client that declares a length and then stalls holds the handler forever
# without this, so every framed read is wrapped in wait_for(READ_TIMEOUT).
READ_TIMEOUT = 10

# Connect timeout (seconds) for every outgoing TCP connection. A contact that
# drops SYNs would otherwise hold up its whole lookup round until the OS gives
# up (about two minutes on Linux), so connections go through connect().
CONNECT_TIMEOUT = 5

# Domain separator for signed STORE records. Covers key, sequence number and
# value so an old signed STORE cannot be replayed to roll a record back.
STORE_DOMAIN_SEPARATOR = b"p2p-net/STORE/v1\0"

# seq is an unsigned 64-bit integer: 0 <= seq < SEQ_LIMIT. Anything outside
# that is refused on STORE and in FIND_VALUE replies (Python ints are
# unbounded, so without the check a peer could sign seq = 10**100).
SEQ_LIMIT = 2 ** 64

ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64

# A node's long-term signing key lives in <key dir>/node_<port>.key unless a
# key_path is passed explicitly. The directory comes from P2P_NET_KEY_DIR
# (one directory, so several nodes in one process keep separate keys).
KEY_DIR_ENV = "P2P_NET_KEY_DIR"
DEFAULT_KEY_DIR = "~/.p2p-net"


def default_key_path(port: int) -> str:
    """<key dir>/node_<port>.key. Port 0 has no default: the OS picks a new
    port on every bind, so every port-0 node would share node_0.key (and one
    identity); such a node must be given an explicit key_path."""
    if port == 0:
        raise ValueError(
            "port 0 has no default key file (every port-0 node would share "
            "node_0.key); pass an explicit key_path"
        )
    key_dir = os.environ.get(KEY_DIR_ENV) or DEFAULT_KEY_DIR
    return os.path.join(os.path.expanduser(key_dir), f"node_{port}.key")


def write_private_file(path: str, data: bytes,
                       keep_existing: bool = False) -> None:
    """Write `data` to `path` crash-safely, readable only by its owner.

    The bytes go to a new temp file in the same directory (mkstemp: created
    with O_EXCL and mode 0600), are fsynced, and only then renamed onto `path`
    with os.replace. A crash at any point leaves either the old file or the
    complete new one at `path`, never a torn one; on an error the temp file is
    removed. With keep_existing, a file that appeared at `path` meanwhile is
    left alone and FileExistsError is raised instead.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=directory, prefix=f".{os.path.basename(path)}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if keep_existing and os.path.exists(path):
            raise FileExistsError(path)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    # Persist the rename itself (the directory entry), where supported.
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def load_or_create_signing_key(path: str) -> Ed25519PrivateKey:
    """Load the Ed25519 key in `path` (PEM, PKCS#8), or create it.

    Names are bound to the signer's public key on every node that stores
    them, so a node must keep its key across restarts to keep updating its
    names. A new key is written with write_private_file (temp file, 0600,
    fsync, rename), so it is never readable by other users and a crash never
    leaves a torn key at `path`. An existing file that doesn't hold a valid
    key raises instead of being replaced, since replacing it would silently
    give up ownership of every name.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        try:
            write_private_file(path, pem, keep_existing=True)
        except FileExistsError:
            # Another process created it first: use that key.
            return load_or_create_signing_key(path)
        print(f"Generated a new signing key in {path}")
        return key

    try:
        key = load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Key file {path} is not a usable private key: {e}")
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"Key file {path} does not hold an Ed25519 key")
    if os.stat(path).st_mode & 0o077:
        print(f"Warning: key file {path} is accessible to other users; "
              f"run chmod 600 on it")
    return key


# Untrusted text (stored values, peer replies, contact addresses) is logged
# through safe_text: repr() escapes control characters, so terminal escape
# sequences in a value never reach the operator's console, and long values
# are cut to LOG_TEXT_LIMIT characters.
LOG_TEXT_LIMIT = 80


def safe_text(text, limit: int = LOG_TEXT_LIMIT) -> str:
    """A printable one-line form of untrusted str or bytes (or None) for
    logging."""
    if isinstance(text, (str, bytes)) and len(text) > limit:
        return f"{text[:limit]!r}... ({len(text)} long)"
    return repr(text)


async def connect(ip: str, port: int):
    """asyncio.open_connection bounded by CONNECT_TIMEOUT (read at call time).

    Raises TimeoutError (an OSError) if the connection isn't up in time.
    """
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(ip, port), CONNECT_TIMEOUT
        )
    except asyncio.TimeoutError:
        raise TimeoutError(
            f"connecting to {safe_text(ip)} port {port} timed out after "
            f"{CONNECT_TIMEOUT}s"
        ) from None


async def write_frame(writer, data: bytes):
    """Write one framed message: a 4-byte big-endian length, then the payload."""
    writer.write(len(data).to_bytes(4, "big") + data)
    await writer.drain()


async def read_frame(reader, max_size: int = MAX_MESSAGE_SIZE,
                     header_timeout: Optional[float] = None):
    """Read one framed message, refusing anything over `max_size` bytes.

    The declared length is checked before the body is read, so a peer cannot
    make us allocate an arbitrarily large buffer. Every read is bounded by
    READ_TIMEOUT (read at call time), so a peer that stalls mid-message is
    dropped instead of holding the handler forever. A long-lived connection
    that is legitimately quiet between messages passes a longer
    `header_timeout` for the wait for the next message; the body of a message
    that has started is always bounded by READ_TIMEOUT.
    """
    if header_timeout is None:
        header_timeout = READ_TIMEOUT
    try:
        length_bytes = await asyncio.wait_for(
            reader.readexactly(4), header_timeout
        )
    except asyncio.TimeoutError:
        raise ValueError("Read timeout: header not received in time")
    length = int.from_bytes(length_bytes, "big")
    if length > max_size:
        raise ValueError(
            f"Rejecting {length}-byte message: over the "
            f"{max_size}-byte cap"
        )
    try:
        return await asyncio.wait_for(
            reader.readexactly(length), READ_TIMEOUT
        )
    except asyncio.TimeoutError:
        raise ValueError("Read timeout: body not received in time")


def sha1_hash(data: str) -> int:
    return int(hashlib.sha1(data.encode()).hexdigest(), 16)


def record_message(key: int, seq: int, value_bytes: bytes) -> bytes:
    """The exact bytes an owner signs for a record: domain separator, then
    key, seq and value separated by NUL (key and seq are decimal, so the
    encoding is unambiguous with the value last)."""
    return (
        STORE_DOMAIN_SEPARATOR
        + str(key).encode()
        + b"\0"
        + str(seq).encode()
        + b"\0"
        + value_bytes
    )


def verify_record(key: int, seq: int, value_bytes: bytes, owner: bytes,
                  signature: bytes) -> bool:
    """True if `signature` is `owner`'s Ed25519 signature over the record."""
    try:
        Ed25519PublicKey.from_public_bytes(owner).verify(
            signature, record_message(key, seq, value_bytes)
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class VerifiedRecord(NamedTuple):
    value: str
    seq: int
    owner: bytes
    signature: bytes


def _is_int(x) -> bool:
    # JSON true/false decode to bool, which is an int subclass in Python.
    return isinstance(x, int) and not isinstance(x, bool)


def valid_seq(seq) -> bool:
    """True if `seq` is an unsigned 64-bit integer (not a bool)."""
    return _is_int(seq) and 0 <= seq < SEQ_LIMIT


def _b64_decode(reply: dict, name: str) -> bytes:
    raw = reply[name]
    if not isinstance(raw, str):
        raise ValueError(f"{name} is not a base64 string")
    try:
        return base64.b64decode(raw, validate=True)
    except ValueError:
        raise ValueError(f"{name} is not valid base64")


def _b64_field(reply: dict, name: str, size: int) -> bytes:
    decoded = _b64_decode(reply, name)
    if len(decoded) != size:
        raise ValueError(f"{name} is {len(decoded)} bytes, expected {size}")
    return decoded


def parse_record_reply(key: int, reply) -> VerifiedRecord:
    """Check a FIND_VALUE record reply for `key` and return it verified.

    The reply carries the whole signed record (key, seq, base64 value, owner
    public key, signature), so the signed message is rebuilt from it and
    checked against the claimed owner. Raises ValueError if anything is
    missing, malformed, for a different key, or the signature does not
    verify.
    """
    if not isinstance(reply, dict):
        raise ValueError("reply is not a JSON object")
    missing = [f for f in ("key", "seq", "value", "owner", "signature")
               if f not in reply]
    if missing:
        raise ValueError(f"missing fields: {', '.join(missing)}")
    reply_key, seq = reply["key"], reply["seq"]
    if not _is_int(reply_key) or reply_key != key:
        raise ValueError("record is for a different key")
    if not valid_seq(seq):
        raise ValueError("seq is not an unsigned 64-bit integer")
    # The value travels base64-encoded, like every other binary field: as a
    # JSON string, control characters escape to six bytes each, which could
    # push a reply for a valid record past MAX_MESSAGE_SIZE.
    value_bytes = _b64_decode(reply, "value")
    if len(value_bytes) > MAX_VALUE_SIZE:
        raise ValueError(f"value is over {MAX_VALUE_SIZE} bytes")
    try:
        value = value_bytes.decode()
    except UnicodeDecodeError:
        raise ValueError("value is not UTF-8 text")
    owner = _b64_field(reply, "owner", ED25519_PUBLIC_KEY_SIZE)
    signature = _b64_field(reply, "signature", ED25519_SIGNATURE_SIZE)
    if not verify_record(reply_key, seq, value_bytes, owner, signature):
        raise ValueError("signature does not verify for the claimed owner")
    return VerifiedRecord(value, seq, owner, signature)


Replica = Tuple[str, int]  # (ip, port) a verified record came from


def select_record(key: int, replies: List[Tuple[Replica, VerifiedRecord]]
                  ) -> Optional[VerifiedRecord]:
    """Pick a lookup's answer from its verified replies, or None.

    `replies` pairs each verified record with the replica that served it
    (the local copy is this node's own ip and port). Records are grouped by
    owner and the owner served by the most distinct replicas wins: a replica
    reached under several contact ids, or more than once, counts once. Then
    the highest seq of that owner's records is returned. A validly signed
    record at seq 2**64-1 from one node therefore can't outvote an owner
    that more replicas agree on. Ties are broken deterministically (equal
    replica counts: lowest owner key; equal seqs: greatest value), so the
    result never depends on reply order. Seeing more than one owner logs a
    warning.
    """
    by_owner: Dict[bytes, Dict[Replica, VerifiedRecord]] = {}
    for replica, record in replies:
        held = by_owner.setdefault(record.owner, {})
        prior = held.get(replica)
        if prior is None or (record.seq, record.value) > (prior.seq, prior.value):
            held[replica] = record
    if not by_owner:
        return None
    owner = min(by_owner, key=lambda o: (-len(by_owner[o]), o))
    if len(by_owner) > 1:
        counts = ", ".join(
            f"{o.hex()[:16]}: {len(by_owner[o])}"
            for o in sorted(by_owner, key=lambda o: (-len(by_owner[o]), o))
        )
        print(f"Warning: key {key} has verified records from {len(by_owner)} "
              f"owners (replicas per owner key: {counts}); using "
              f"{owner.hex()[:16]}. Pin the owner (expected_owner) to stop "
              f"relying on the majority.")
    return max(by_owner[owner].values(), key=lambda r: (r.seq, r.value))


def node_entry(node: "Node") -> dict:
    """The JSON form of a contact in a FIND_NODE / FIND_VALUE reply. The NAT
    fields are included when known, so contact lists carry the reachability
    flag alongside the address."""
    entry = {'id': node.id, 'ip': node.ip, 'port': node.port}
    if node.reachable is not None:
        entry['reachable'] = node.reachable
    if node.virtual_ip is not None:
        entry['virtual_ip'] = node.virtual_ip
    return entry


def parse_node_list(entries) -> List["Node"]:
    """Turn an untrusted JSON node list into Node objects, or raise ValueError.

    Ids must be ints in [0, 2**ID_BITS), ips strings and ports ints in
    1..65535; a string or list id would otherwise raise later in the lookup's
    XOR sort or set(), outside any try block. The optional NAT fields
    ('reachable' bool, 'virtual_ip' string) are carried onto the Node.
    """
    if not isinstance(entries, list):
        raise ValueError("node list is not a list")
    nodes = []
    for n in entries:
        if not isinstance(n, dict):
            raise ValueError("node entry is not an object")
        node_id, ip, port = n.get('id'), n.get('ip'), n.get('port')
        if not (_is_int(node_id) and 0 <= node_id < 2 ** ID_BITS):
            raise ValueError("node id is not a valid id")
        if not isinstance(ip, str):
            raise ValueError("node ip is not a string")
        if not (_is_int(port) and 0 < port < 65536):
            raise ValueError("node port is not a valid port")
        reachable = n.get('reachable')
        if reachable is not None and not isinstance(reachable, bool):
            raise ValueError("reachable is not a bool")
        virtual_ip = n.get('virtual_ip')
        if virtual_ip is not None and not isinstance(virtual_ip, str):
            raise ValueError("virtual ip is not a string")
        nodes.append(Node(node_id, ip, port, reachable=reachable,
                          virtual_ip=virtual_ip))
    return nodes


class Node:
    def __init__(self, id: int, ip: str, port: int, public_key: bytes = None,
                 reachable: Optional[bool] = None,
                 virtual_ip: Optional[str] = None):
        self.id = id
        self.ip = ip
        self.port = port
        self.public_key = public_key
        # NAT traversal: whether the introduction server could dial this
        # contact back at its advertised address, and the contact's virtual
        # ip (the address relay requests to it are addressed by). Both are
        # None when unknown (e.g. a contact learned from a FIND_NODE reply
        # before this node joined the introduction server).
        self.reachable = reachable
        self.virtual_ip = virtual_ip

    def __eq__(self, other):
        return self.id == other.id

    def __hash__(self):
        return hash(self.id)


class KBucket:
    def __init__(self):
        self.nodes: List[Node] = []

    def add(self, node: Node):
        # Kademlia least-recently-seen order: seeing a known peer again moves
        # it to the tail of its bucket instead of just dropping it.
        if node in self.nodes:
            self.nodes.remove(node)
            self.nodes.append(node)
        elif len(self.nodes) < K:
            self.nodes.append(node)
        return len(self.nodes) < K


class RoutingTable:
    def __init__(self, our_id: int):
        self.our_id = our_id
        self.buckets = [KBucket() for _ in range(ID_BITS)]

    def add(self, node: Node):
        bucket_index = (ID_BITS - (self.our_id ^ node.id).bit_length() - 1)
        return self.buckets[bucket_index].add(node)

    def find_closest(self, target_id: int) -> List[Node]:
        bucket_index = (ID_BITS - (self.our_id ^ target_id).bit_length() - 1)
        nodes = self.buckets[bucket_index].nodes[:]
        if len(nodes) < K:
            for i in range(1, ID_BITS):
                if bucket_index - i >= 0:
                    nodes.extend(self.buckets[bucket_index - i].nodes)
                if bucket_index + i < ID_BITS:
                    nodes.extend(self.buckets[bucket_index + i].nodes)
                if len(nodes) >= K:
                    break
        return sorted(nodes, key=lambda n: n.id ^ target_id)[:K]


class KademliaProtocol:
    def __init__(self, node_id: int, kademlia_node):
        self.node_id = node_id
        self.kademlia_node = kademlia_node

    async def _send_message(self, writer, data: bytes):
        await write_frame(writer, data)

    async def _read_message(self, reader):
        return await read_frame(reader)

    async def ping(self, writer):
        await self._send_message(writer, b"PING")

    def store_payload(self, key: int, value: str, seq: int = None,
                      signature: bytes = None) -> bytes:
        # Sign a domain-separated message covering key, sequence number and
        # value, with the value carried base64-encoded so values of any bytes
        # (including spaces and the empty string) round-trip exactly. A caller
        # that already signed the record (KademliaNode.store) passes the
        # signature and its seq so every replica carries the same signature.
        value_bytes = value.encode() if isinstance(value, str) else value
        if signature is None:
            if seq is None:
                seq = time.time_ns()
            signature = self.kademlia_node.sign_record(key, seq, value_bytes)
        elif seq is None:
            raise ValueError("a prebuilt signature needs the seq it signs")
        public_key_bytes = self.kademlia_node.owner_public_key

        return (
            f"STOR {key} {seq} "
            f"{base64.b64encode(value_bytes).decode()} "
            f"{base64.b64encode(public_key_bytes).decode()} "
            f"{base64.b64encode(signature).decode()}"
        ).encode()

    async def store(self, writer, key: int, value: str, seq: int = None,
                    signature: bytes = None):
        await self._send_message(
            writer, self.store_payload(key, value, seq, signature)
        )

    async def find_node(self, writer, target_id: int):
        message = f"FIND_NODE {target_id}".encode()
        await self._send_message(writer, message)

    async def find_value(self, writer, key: int):
        message = f"FIND_VALUE {key}".encode()
        await self._send_message(writer, message)

    async def handle_ping(self) -> bytes:
        return b"PONG"

    async def handle_store(self, payload: bytes) -> bytes:
        # payload: b"STOR <key> <seq> <base64 value> <base64 public_key>
        #          <base64 signature>"  (exactly five space-separated tokens
        #          after STOR; the value is base64 so any bytes round-trip).
        try:
            # Split on single spaces so an empty base64 value (an empty token
            # between two spaces) is preserved; str.split() would collapse it.
            parts = payload.decode().split(" ")
            if len(parts) != 6 or parts[0] != "STOR":
                raise ValueError("bad STORE shape")
            _, key_s, seq_s, value_b64, public_key_b64, signature_b64 = parts
            key = int(key_s)
            seq = int(seq_s)
            value_bytes = base64.b64decode(value_b64)
            # Values are UTF-8 text; anything else is rejected here rather
            # than raising later and dropping the connection without a reply.
            value = value_bytes.decode()
            public_key_bytes = base64.b64decode(public_key_b64)
            signature = base64.b64decode(signature_b64)
        except Exception:
            print("Rejecting malformed STORE: missing or invalid fields")
            return b"REJECTED"

        if len(value_bytes) > MAX_VALUE_SIZE:
            print(f"Rejecting STORE: value for key {key} is "
                  f"{len(value_bytes)} bytes, over {MAX_VALUE_SIZE}")
            return b"REJECTED"

        if not valid_seq(seq):
            print(f"Rejecting STORE: seq for key {key} is not an unsigned "
                  f"64-bit integer")
            return b"REJECTED"

        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        except Exception:
            print("Rejecting STORE: public key is not a valid Ed25519 key")
            return b"REJECTED"

        try:
            public_key.verify(signature, record_message(key, seq, value_bytes))
        except InvalidSignature:
            print(f"Rejecting STORE: bad signature for key {key}")
            return b"REJECTED"

        accepted, message = self.kademlia_node.put_record(
            key, public_key_bytes, seq, value, signature
        )
        if accepted:
            print(message)
            return b"OK"
        else:
            print(f"Rejecting STORE: {message}")
            return b"REJECTED"

    @staticmethod
    def _parse_id_request(payload: bytes, command: str) -> Optional[int]:
        """Parse b"<command> <id>" into an id in [0, 2**ID_BITS), or None.

        Out-of-range ids are refused too: find_closest would index past the
        bucket list for ids of more than 2 * ID_BITS bits.
        """
        try:
            parts = payload.decode().split()
            if len(parts) != 2 or parts[0] != command:
                return None
            target = int(parts[1])
        except ValueError:  # includes UnicodeDecodeError
            return None
        if not 0 <= target < 2 ** ID_BITS:
            return None
        return target

    async def handle_find_node(self, payload: bytes) -> bytes:
        # payload: b"FIND_NODE <target_id>"
        target_id = self._parse_id_request(payload, "FIND_NODE")
        if target_id is None:
            print("Malformed FIND_NODE request: replying with no nodes")
            return b"[]"
        closest_nodes = self.kademlia_node.routing_table.find_closest(target_id)
        response = json.dumps(
            [node_entry(node) for node in closest_nodes]
        ).encode()
        return response

    async def handle_find_value(self, payload: bytes) -> bytes:
        # payload: b"FIND_VALUE <key>"
        key = self._parse_id_request(payload, "FIND_VALUE")
        if key is None:
            print("Malformed FIND_VALUE request: replying with no nodes")
            return json.dumps({'nodes': []}).encode()
        if key in self.kademlia_node.data:
            # Return the whole signed record (key, seq, value, owner public
            # key and signature) so the caller can verify it on its own; this
            # node is not trusted to vouch for it. The value is base64, like
            # the other binary fields, so its size on the wire is 4/3 of the
            # value however many control characters it holds.
            owner, seq, value, signature = self.kademlia_node.data[key]
            response = json.dumps({
                'key': key,
                'value': base64.b64encode(value.encode()).decode(),
                'seq': seq,
                'owner': base64.b64encode(owner).decode(),
                'signature': base64.b64encode(signature).decode(),
            })
        else:
            closest_nodes = self.kademlia_node.routing_table.find_closest(key)
            response = json.dumps(
                {'nodes': [node_entry(node) for node in closest_nodes]}
            )
        return response.encode()


class KademliaNode:
    def __init__(self, id: int, ip: str, port: int,
                 key_path: Optional[str] = None):
        self.id = id
        self.ip = ip
        self.port = port
        self.routing_table = RoutingTable(id)
        # Maps key -> (owner public key bytes, seq, value, signature). The
        # owner key is the Ed25519 public key of whoever first stored the name
        # on this node (see KademliaProtocol.handle_store). seq is a uint64
        # written when the owner calls store(); it survives restarts because
        # no state is saved. The signature is the owner's signature over
        # record_message(key, seq, value), so any copy can be re-verified.
        self.data: Dict[int, Tuple[bytes, int, str, bytes]] = {}
        # Long-term signing key used to sign records this node stores. It is
        # loaded from (or created in) key_path so it survives restarts: other
        # nodes bind this node's names to it on first use. A port-0 node has
        # no default path and must pass key_path (see default_key_path).
        self.key_path = key_path or default_key_path(port)
        self.signing_key = load_or_create_signing_key(self.key_path)
        # This node's own public key, the owner recorded for names it stores.
        self.owner_public_key = self.signing_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.protocol = KademliaProtocol(id, self)

    def sign_record(self, key: int, seq: int, value_bytes: bytes) -> bytes:
        return self.signing_key.sign(record_message(key, seq, value_bytes))

    def put_record(self, key: int, owner: bytes, seq: int, value: str,
                   signature: bytes) -> Tuple[bool, str]:
        """Apply this node's storage rules to a record whose signature has
        already been checked; return (accepted, message to log).

        Used for STOREs from peers and for this node's own local copy alike.
        Names are owned on first use: the first record for a name binds it to
        the signer's public key. A record signed by a different key is
        refused; the owner can keep updating the record, but only with a
        strictly greater seq (an equal seq with the identical value is an
        idempotent no-op). The signature is kept with the record so
        FIND_VALUE can hand out a self-verifying record.
        """
        record = self.data.get(key)
        if record is None:
            if len(self.data) >= MAX_RECORDS:
                return False, (f"node is full ({MAX_RECORDS} records); not "
                               f"taking new key {key}")
            self.data[key] = (owner, seq, value, signature)
            return True, f"Stored key-value pair: {key} {safe_text(value)}"

        stored_owner, stored_seq, stored_value, _ = record
        if stored_owner != owner:
            return False, f"key {key} is owned by a different key"
        if seq > stored_seq:
            self.data[key] = (owner, seq, value, signature)
            return True, f"Updated key-value pair: {key} {safe_text(value)}"
        if seq == stored_seq and value == stored_value:
            return True, f"Idempotent re-store of key {key}: no change"
        return False, (f"key {key} seq {seq} not greater than stored seq "
                       f"{stored_seq}")

    async def bootstrap(self, bootstrap_nodes: List[Node]):
        for node in bootstrap_nodes:
            await self.ping(node)

    async def ping(self, node: Node):
        try:
            reader, writer = await connect(node.ip, node.port)
            await self.protocol.ping(writer)
            response = await self.protocol._read_message(reader)
            if response == b"PONG":
                self.routing_table.add(node)
                print(f"Successfully pinged and added node {node.id}")
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            print(f"Failed to ping node {node.id} : Tried Pinging "
                  f"{safe_text(node.ip)} port {node.port} : {e}")

    async def store(self, key: int, value: str):
        # One seq and one signature for this store op, carried unchanged to
        # the local copy and every replica so the record is identical (and
        # verifiable) wherever it is stored.
        value_bytes = value.encode()
        if len(value_bytes) > MAX_VALUE_SIZE:
            raise ValueError(f"value is {len(value_bytes)} bytes; the limit "
                             f"is MAX_VALUE_SIZE = {MAX_VALUE_SIZE}")
        seq = time.time_ns()
        signature = self.sign_record(key, seq, value_bytes)
        # This node is a candidate replica too: it is never in its own routing
        # table, so without adding it here the local copy was never written.
        me = Node(self.id, self.ip, self.port)
        candidates = set(self.routing_table.find_closest(key)) | {me}
        nodes = sorted(candidates, key=lambda n: n.id ^ key)[:K]
        store_tasks = []
        for node in nodes:
            if node.id == self.id:
                # Same rules as a STORE from a peer: never take over a name
                # owned by a different key, even in our local copy.
                accepted, message = self.put_record(
                    key, self.owner_public_key, seq, value, signature
                )
                if not accepted:
                    print(f"Not storing local copy: {message}")
            else:
                store_tasks.append(
                    self._store_on_node(node, key, value, seq, signature)
                )
        await asyncio.gather(*store_tasks)

    async def _store_on_node(self, node: Node, key: int, value: str, seq: int,
                             signature: bytes = None):
        try:
            reader, writer = await connect(node.ip, node.port)
            await self.protocol.store(writer, key, value, seq, signature)
            response = await self.protocol._read_message(reader)
            if response == b"OK":
                print(f"Successfully stored value {safe_text(value)} on node {node.id}")
            else:
                print(f"Failed to store value {safe_text(value)} on node "
                      f"{node.id}: {safe_text(response)}")
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            print(f"Failed to store key {key} on node {node.id}: {e}")

    async def find_node(self, target_id: int) -> List[Node]:
        nodes = self.routing_table.find_closest(target_id)
        if not nodes:
            return []
        queried_nodes = set()
        while True:
            budget = min(ALPHA, MAX_LOOKUP_QUERIES - len(queried_nodes))
            unqueried = [node for node in nodes if node not in queried_nodes][:budget]
            if not unqueried:
                break
            query_tasks = [self._find_node_on_node(node, target_id) for node in unqueried]
            results = await asyncio.gather(*query_tasks)
            for result in results:
                if result:
                    nodes.extend(result)
            queried_nodes.update(unqueried)
            nodes = sorted(set(nodes), key=lambda n: n.id ^ target_id)[:K]
        return nodes

    async def _find_node_on_node(self, node: Node, target_id: int) -> List[Node]:
        try:
            reader, writer = await connect(node.ip, node.port)
            await self.protocol.find_node(writer, target_id)
            response = await self.protocol._read_message(reader)
            writer.close()
            await writer.wait_closed()
            return parse_node_list(json.loads(response.decode()))
        except Exception as e:
            print(f"Failed to find_node on {node.id}: {e}")
            return []

    async def find_value(
        self, key: int, expected_owner: Optional[bytes] = None
    ) -> Tuple[Optional[str], List[Node]]:
        """Look up `key` and return (value, []) or (None, closest nodes).

        See find_record for how the answer is chosen.
        """
        record, nodes = await self.find_record(key, expected_owner)
        return (record.value if record is not None else None), nodes

    async def find_record(
        self, key: int, expected_owner: Optional[bytes] = None
    ) -> Tuple[Optional[VerifiedRecord], List[Node]]:
        """Look up `key`; return (verified record, []) or (None, closest
        nodes).

        Every candidate record, the local copy included, must carry a valid
        owner signature; replies that fail verification count as no answer.
        The lookup walks the K closest nodes instead of stopping at the first
        hit. With `expected_owner` set, only records signed by that public
        key are accepted and the highest seq wins, so a node serving an older
        (but genuinely signed) record loses to any fresher replica. Without
        it, select_record picks the owner served by the most distinct
        replicas, then that owner's highest seq.
        """
        print(f"find_value for key {key} on node {self.id}")

        candidates: List[Tuple[Replica, VerifiedRecord]] = []
        local = self.data.get(key)
        if local is not None:
            owner, seq, value, signature = local
            if not (isinstance(value, str) and valid_seq(seq)
                    and verify_record(key, seq, value.encode(), owner, signature)):
                print(f"Ignoring local record for key {key}: signature does not verify")
            elif expected_owner is not None and owner != expected_owner:
                print(f"Ignoring local record for key {key}: not the expected owner")
            else:
                candidates.append(((self.ip, self.port),
                                   VerifiedRecord(value, seq, owner, signature)))

        nodes = self.routing_table.find_closest(key)
        queried_nodes = set()
        while True:
            budget = min(ALPHA, MAX_LOOKUP_QUERIES - len(queried_nodes))
            unqueried = [node for node in nodes if node not in queried_nodes][:budget]
            if not unqueried:
                break
            query_tasks = [
                self._find_value_on_node(node, key, expected_owner)
                for node in unqueried
            ]
            results = await asyncio.gather(*query_tasks)
            for node, result in zip(unqueried, results):
                if isinstance(result, VerifiedRecord):
                    candidates.append(((node.ip, node.port), result))
                elif result:
                    nodes.extend(result)
            queried_nodes.update(unqueried)
            nodes = sorted(set(nodes), key=lambda n: n.id ^ key)[:K]

        best = select_record(key, candidates)
        if best is not None:
            return best, []
        return None, nodes

    async def _find_value_on_node(
        self, node: Node, key: int, expected_owner: Optional[bytes] = None
    ) -> Union[VerifiedRecord, List[Node], None]:
        try:
            reader, writer = await connect(node.ip, node.port)
            try:
                await self.protocol.find_value(writer, key)
                response = await self.protocol._read_message(reader)
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception as e:
            print(f"Failed to find_value on {node.id}: {e}")
            return None

        # The reply is untrusted. A record must verify against the owner key
        # it claims (and match expected_owner if given); anything that can't
        # be parsed or verified counts as no answer from this node. The broad
        # except also covers RecursionError from deeply nested JSON.
        try:
            result = json.loads(response.decode())
            if isinstance(result, dict) and 'value' in result:
                record = parse_record_reply(key, result)
                if expected_owner is not None and record.owner != expected_owner:
                    raise ValueError("record is signed by a different owner "
                                     "than expected")
                return record
            if isinstance(result, dict) and 'nodes' in result:
                return parse_node_list(result['nodes'])
            raise ValueError("reply has neither a record nor a node list")
        except Exception as e:
            print(f"Rejecting FIND_VALUE reply from node {node.id}: {e}")
            return None

    async def listen(self):
        server = await asyncio.start_server(self.handle_connection, self.ip, self.port)
        print(f"Kademlia node listening on {self.ip}:{self.port}")
        async with server:
            await server.serve_forever()

    async def handle_connection(self, reader, writer):
        try:
            data = await self.protocol._read_message(reader)
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, OSError, ValueError):
            # ValueError covers messages whose length prefix exceeds the cap.
            writer.close()
            await writer.wait_closed()
            return

        try:
            reply = await self.dispatch(data)
            if reply is not None:
                await self.protocol._send_message(writer, reply)
        except Exception as e:
            # E.g. the peer hung up before the reply was written: log it and
            # close instead of leaving an unhandled exception in the server.
            print(f"Error handling request: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def dispatch(self, data: bytes) -> Optional[bytes]:
        """Handle one framed request payload and return the framed reply
        (None for an unknown command: the caller then sends nothing).

        Split out of handle_connection so a relayed message (which arrives
        over the introduction server's relay channel, not a TCP connection to
        this node) can be answered the same way.
        """
        if data == b"PING":
            return await self.protocol.handle_ping()
        if data[:5] == b"STOR ":
            return await self.protocol.handle_store(data)
        if data[:9] == b"FIND_NODE":
            return await self.protocol.handle_find_node(data)
        if data[:10] == b"FIND_VALUE":
            return await self.protocol.handle_find_value(data)
        return None
