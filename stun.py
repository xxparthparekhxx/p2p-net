"""STUN client (RFC 8489, stdlib only): Binding requests over UDP and TCP, and
a test of whether a NAT's mapping depends on the destination.

A Binding request asks a public STUN server which address and port it sees
the request come from (the "reflexive" or "mapped" address). Asking two
servers from the *same local port* tells the two kinds of NAT apart:

  endpoint-independent  both servers see the same address: the NAT reuses one
                        external port for every destination, so a peer that
                        is told that port can be reached (hole punching can
                        work);
  endpoint-dependent    the servers see different ports ("symmetric" NAT):
                        the port a peer would be told is not the one used
                        for the peer, so hole punching cannot work.

For TCP hole punching the mapping that matters is the one for the node's
listening port, so the TCP queries are made from a socket bound to that port
(reusable_socket sets SO_REUSEADDR and SO_REUSEPORT, so it can share the port
with the listener). A UDP result says little about it: a NAT keeps separate
TCP and UDP mappings and need not treat them alike.

Everything here fails soft: a server that does not answer, answers with
garbage or with an error is an exception (StunError, or OSError for the
network), never a hang. All waits are bounded.
"""

import asyncio
import ipaddress
import os
import socket
import struct
from typing import List, NamedTuple, Optional, Sequence, Tuple

Address = Tuple[str, int]

# Public servers that answered a Binding request. UDP: Google, Cloudflare,
# Twilio, Nextcloud, Telnyx. TCP: Google, Cloudflare and Twilio did not answer
# over TCP when this was checked (see the readme), so the TCP list holds only
# servers that did. Servers that share an IP (stun.signalwire.com and
# stun.freeswitch.org) are listed once, since the mapping test needs servers
# at different IPs.
DEFAULT_UDP_SERVERS: List[Address] = [
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("global.stun.twilio.com", 3478),
    ("stun.nextcloud.com", 3478),
    ("stun.telnyx.com", 3478),
]
DEFAULT_TCP_SERVERS: List[Address] = [
    ("stun.nextcloud.com", 3478),
    ("stun.telnyx.com", 3478),
    ("stun.signalwire.com", 3478),
    ("stun.voip.blackberry.com", 3478),
]

# UDP is retransmitted with a doubling timeout: RFC 8489 6.2.1 says an initial
# RTO of at least 500 ms and up to 7 requests; this sends 3, so a dead server
# costs 0.5 + 1 + 2 = 3.5 s instead of 39.5 s. TCP has no STUN-level
# retransmission: one transaction (resolve, connect, request, response) gets
# STUN_TCP_TIMEOUT.
STUN_UDP_RTO = 0.5
STUN_UDP_SENDS = 3
STUN_TCP_TIMEOUT = 5
# Name resolution is bounded too (getaddrinfo can block for a long time).
STUN_RESOLVE_TIMEOUT = 3
# detect_mapping queries (at most) this many servers of the list, at once.
STUN_MAX_QUERIES = 4
# A Binding response is a few dozen bytes; anything with a bigger body is not
# one, and the declared length is checked before the body is read.
STUN_MAX_BODY_SIZE = 1024

MAGIC_COOKIE = 0x2112A442
HEADER_SIZE = 20
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
BINDING_ERROR = 0x0111

ATTR_MAPPED_ADDRESS = 0x0001
ATTR_ERROR_CODE = 0x0009
ATTR_XOR_MAPPED_ADDRESS = 0x0020
# Attributes in the comprehension-required range (below 0x8000) that a client
# may skip: RFC 3489 ones that servers still send (SOURCE-ADDRESS,
# CHANGED-ADDRESS, REFLECTED-FROM) and the authentication ones (USERNAME,
# MESSAGE-INTEGRITY, UNKNOWN-ATTRIBUTES, REALM, NONCE,
# MESSAGE-INTEGRITY-SHA256), which an unauthenticated Binding request has no
# use for. Any other unknown attribute in that range fails the transaction
# (RFC 8489 6.3.3); unknown ones above 0x8000 are optional and skipped.
SKIPPED_ATTRIBUTES = {0x0004, 0x0005, 0x000B, 0x0006, 0x0008, 0x000A, 0x0014,
                      0x0015, 0x001C}
KNOWN_ATTRIBUTES = SKIPPED_ATTRIBUTES | {
    ATTR_MAPPED_ADDRESS, ATTR_ERROR_CODE, ATTR_XOR_MAPPED_ADDRESS}

ENDPOINT_INDEPENDENT = "endpoint-independent"
ENDPOINT_DEPENDENT = "endpoint-dependent"
UNKNOWN = "unknown"


class StunError(Exception):
    """A STUN transaction failed: no usable answer."""


class StunMalformed(StunError):
    """A message that is not an answer to our request (too short, bad header,
    wrong transaction id). A UDP client ignores these and keeps waiting."""


class Answer(NamedTuple):
    server: Address            # the server as configured
    server_ip: str             # the IP it resolved to
    address: Address           # the (ip, port) it saw us at


class MappingResult(NamedTuple):
    mapping: str               # ENDPOINT_INDEPENDENT, ENDPOINT_DEPENDENT or UNKNOWN
    answers: List[Answer]

    @property
    def address(self) -> Optional[Address]:
        """The first reflexive address a server reported, if any."""
        return self.answers[0].address if self.answers else None


def new_transaction_id() -> bytes:
    return os.urandom(12)


def build_binding_request(transaction_id: bytes) -> bytes:
    return struct.pack(">HHI", BINDING_REQUEST, 0, MAGIC_COOKIE) + transaction_id


def _decode_address(value: bytes, transaction_id: bytes, xor: bool) -> Address:
    """The (ip, port) in a MAPPED-ADDRESS or XOR-MAPPED-ADDRESS value: a
    reserved byte, the family (1 = IPv4, 2 = IPv6), the port and the address.
    The XOR form XORs the port with the top 16 bits of the magic cookie and
    the address with the cookie (IPv4) or the cookie and the transaction id
    (IPv6)."""
    if len(value) < 4:
        raise StunError("address attribute is shorter than 4 bytes")
    family, port = value[1], int.from_bytes(value[2:4], "big")
    raw = value[4:]
    if family == 1 and len(raw) == 4:
        af, key = socket.AF_INET, struct.pack(">I", MAGIC_COOKIE)
    elif family == 2 and len(raw) == 16:
        af, key = socket.AF_INET6, struct.pack(">I", MAGIC_COOKIE) + transaction_id
    else:
        raise StunError(f"address attribute with family {family} and "
                        f"{len(raw)} address bytes")
    if xor:
        port ^= MAGIC_COOKIE >> 16
        raw = bytes(a ^ b for a, b in zip(raw, key))
    ip = ipaddress.ip_address(socket.inet_ntop(af, raw))
    if port == 0 or ip.is_unspecified or ip.is_multicast:
        raise StunError("the reported address is not a usable endpoint")
    return str(ip), port


def _error_text(value: bytes) -> str:
    """'code reason' of an ERROR-CODE value (bounded: it is the server's)."""
    if len(value) < 4:
        return "error response"
    code = (value[2] & 0x07) * 100 + value[3]
    reason = value[4:68].decode("utf-8", "replace")
    return f"error {code} {reason!r}"


def parse_binding_response(data: bytes, transaction_id: bytes) -> Address:
    """The mapped (ip, port) in a Binding success response to the request with
    `transaction_id`.

    Raises StunMalformed for a message that is not an answer to this request
    (bad header, length that does not match, wrong transaction id, not a
    Binding response) and StunError for an answer that is useless: an error
    response, an unknown comprehension-required attribute, a truncated or
    invalid attribute, or no address at all. XOR-MAPPED-ADDRESS is preferred;
    MAPPED-ADDRESS (older servers) is the fallback.
    """
    if len(data) < HEADER_SIZE:
        raise StunMalformed("shorter than the 20-byte header")
    message_type, length, cookie = struct.unpack(">HHI", data[:8])
    if message_type & 0xC000 or cookie != MAGIC_COOKIE:
        raise StunMalformed("not a STUN message")
    if length % 4 or len(data) != HEADER_SIZE + length:
        raise StunMalformed("length does not match the message")
    if data[8:HEADER_SIZE] != transaction_id:
        raise StunMalformed("transaction id does not match the request")
    if message_type not in (BINDING_SUCCESS, BINDING_ERROR):
        raise StunMalformed(f"not a Binding response (type {message_type:#06x})")

    xor_mapped = mapped = error = None
    body, pos = data[HEADER_SIZE:], 0
    while pos < len(body):
        attr_type, attr_length = struct.unpack(">HH", body[pos:pos + 4])
        pos += 4
        padded = attr_length + (-attr_length % 4)
        if pos + padded > len(body):
            raise StunError("attribute runs past the end of the message")
        value = body[pos:pos + attr_length]
        pos += padded
        if attr_type == ATTR_XOR_MAPPED_ADDRESS and xor_mapped is None:
            xor_mapped = _decode_address(value, transaction_id, xor=True)
        elif attr_type == ATTR_MAPPED_ADDRESS and mapped is None:
            mapped = _decode_address(value, transaction_id, xor=False)
        elif attr_type == ATTR_ERROR_CODE:
            error = _error_text(value)
        elif attr_type < 0x8000 and attr_type not in KNOWN_ATTRIBUTES:
            raise StunError(f"unknown comprehension-required attribute "
                            f"{attr_type:#06x}")

    if message_type == BINDING_ERROR:
        raise StunError(error or "error response")
    address = xor_mapped or mapped
    if address is None:
        raise StunError("response has no mapped address")
    return address


def _family(ip: str) -> int:
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


def abort_on_close(sock) -> None:
    """Make close() reset the TCP connection instead of ending it with a FIN.

    A connection that closes normally leaves a TIME_WAIT entry (about a
    minute) at the closing end, and while it exists the same local port
    cannot connect to the same remote address again. A node connects out from
    its one listening port, again and again, to the same STUN servers and
    peers, so its connections must not leave one. Anything still unsent when
    it closes is lost."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                    struct.pack("ii", 1, 0))


def reusable_socket(local_addr: Optional[Address] = None,
                    kind: int = socket.SOCK_STREAM) -> socket.socket:
    """A non-blocking socket bound to `local_addr` with SO_REUSEADDR and
    SO_REUSEPORT, so it can share its port with a listener (and with other
    such sockets). That is what lets a node connect out *from* its listening
    port: the NAT then maps the listening port, which is the mapping a hole
    punch uses. Linux needs SO_REUSEPORT on every socket that shares the
    port, and the same user for all of them. A TCP socket made here resets
    its connection when closed (abort_on_close)."""
    ip, port = local_addr or ("0.0.0.0", 0)
    sock = socket.socket(_family(ip), kind)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        if kind == socket.SOCK_STREAM:
            abort_on_close(sock)
        sock.setblocking(False)
        sock.bind((ip, port))
    except BaseException:
        sock.close()
        raise
    return sock


async def connect_from(local_addr: Address, remote_addr: Address,
                       timeout: float):
    """Open a TCP connection to `remote_addr` from `local_addr` (a port that
    may be shared, see reusable_socket); returns (reader, writer). Raises
    OSError (TimeoutError after `timeout` seconds) and never leaks the
    socket."""
    loop = asyncio.get_running_loop()
    sock = reusable_socket(local_addr)
    try:
        try:
            await asyncio.wait_for(loop.sock_connect(sock, remote_addr),
                                   timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"connecting to {remote_addr[0]!r} port "
                               f"{remote_addr[1]} timed out after "
                               f"{timeout}s") from None
        return await asyncio.open_connection(sock=sock)
    except BaseException:
        sock.close()
        raise


async def _resolve(server: Address, kind: int, family: int) -> str:
    """The IP `server` resolves to (the first address of `family`)."""
    host, port = server
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                host, port, family=family, type=kind), STUN_RESOLVE_TIMEOUT)
    except asyncio.TimeoutError:
        raise StunError(f"resolving {host!r} timed out") from None
    return infos[0][4][0]


class _UdpClient(asyncio.DatagramProtocol):
    """One UDP socket that can run several Binding transactions at once.
    Replies are matched by transaction id and must come from the address the
    request went to; anything else is dropped."""

    def __init__(self):
        self.transport = None
        self.pending = {}   # transaction id -> (server address, future)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        entry = self.pending.get(data[8:HEADER_SIZE])
        if entry is None:
            return
        server_addr, future = entry
        if addr[:2] != server_addr[:2] or future.done():
            return
        try:
            future.set_result(parse_binding_response(data, data[8:HEADER_SIZE]))
        except StunMalformed:
            pass   # not an answer to this request: keep waiting
        except StunError as e:
            future.set_exception(e)

    async def query(self, server_addr: Address) -> Address:
        transaction_id = new_transaction_id()
        request = build_binding_request(transaction_id)
        future = asyncio.get_running_loop().create_future()
        self.pending[transaction_id] = (server_addr, future)
        try:
            rto = STUN_UDP_RTO
            for _ in range(STUN_UDP_SENDS):
                self.transport.sendto(request, server_addr)
                await asyncio.wait({future}, timeout=rto)
                if future.done():
                    return future.result()
                rto *= 2
            raise StunError(f"no answer from {server_addr[0]} after "
                            f"{STUN_UDP_SENDS} requests")
        finally:
            del self.pending[transaction_id]
            future.cancel()


async def _query_udp(servers: Sequence[Address],
                     local_addr: Optional[Address]) -> list:
    """Ask each server from one UDP socket bound to `local_addr`: an Answer
    per server, or the exception that server's query ended with."""
    loop = asyncio.get_running_loop()
    sock = reusable_socket(local_addr, socket.SOCK_DGRAM)
    transport = None
    try:
        transport, client = await loop.create_datagram_endpoint(
            _UdpClient, sock=sock)

        async def one(server):
            ip = await _resolve(server, socket.SOCK_DGRAM, sock.family)
            address = await client.query((ip, server[1]))
            return Answer(server, ip, address)

        return await asyncio.gather(*(one(s) for s in servers),
                                    return_exceptions=True)
    finally:
        if transport is not None:
            transport.close()
        else:
            sock.close()


async def _query_tcp_once(server: Address, local_addr: Address) -> Answer:
    ip = await _resolve(server, socket.SOCK_STREAM, _family(local_addr[0]))
    transaction_id = new_transaction_id()
    reader, writer = await connect_from(local_addr, (ip, server[1]),
                                        STUN_TCP_TIMEOUT)
    try:
        writer.write(build_binding_request(transaction_id))
        await writer.drain()
        header = await reader.readexactly(HEADER_SIZE)
        length = int.from_bytes(header[2:4], "big")
        if length > STUN_MAX_BODY_SIZE:
            raise StunError(f"{length}-byte message body is over the "
                            f"{STUN_MAX_BODY_SIZE}-byte cap")
        body = await reader.readexactly(length)
        return Answer(server, ip,
                      parse_binding_response(header + body, transaction_id))
    except asyncio.IncompleteReadError:
        raise StunError("the server closed the connection before it "
                        "answered") from None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _query_tcp(server: Address, local_addr: Address) -> Answer:
    try:
        return await asyncio.wait_for(_query_tcp_once(server, local_addr),
                                      STUN_TCP_TIMEOUT)
    except asyncio.TimeoutError:
        raise StunError(f"no answer from {server[0]!r} within "
                        f"{STUN_TCP_TIMEOUT}s") from None


async def binding_request(server: Address, protocol: str = "udp",
                          local_addr: Optional[Address] = None) -> Address:
    """Ask one STUN server for our mapped (ip, port). `protocol` is "udp" or
    "tcp"; the request leaves from `local_addr` (default: any address and a
    free port). Raises StunError, or OSError when the network fails."""
    answer = (await _query([server], protocol, local_addr))[0]
    if isinstance(answer, Exception):
        raise answer
    return answer.address


async def _query(servers: Sequence[Address], protocol: str,
                 local_addr: Optional[Address]) -> list:
    """An Answer or an exception per server, all queried from one local port
    (one UDP socket; for TCP one socket per query, all bound to that port)."""
    if protocol not in ("udp", "tcp"):
        raise ValueError(f"protocol must be 'udp' or 'tcp', not {protocol!r}")
    local_addr = local_addr or ("0.0.0.0", 0)
    if protocol == "udp":
        return await _query_udp(servers, local_addr)
    # Port 0 would give every TCP query its own port; hold one so they share.
    anchor = None
    if local_addr[1] == 0:
        anchor = reusable_socket(local_addr)
        local_addr = (local_addr[0], anchor.getsockname()[1])
    try:
        return await asyncio.gather(
            *(_query_tcp(s, local_addr) for s in servers),
            return_exceptions=True)
    finally:
        if anchor is not None:
            anchor.close()


async def detect_mapping(servers: Optional[Sequence[Address]] = None,
                         protocol: str = "tcp",
                         local_addr: Optional[Address] = None
                         ) -> MappingResult:
    """Classify the NAT's mapping from the same local port.

    Queries the first STUN_MAX_QUERIES servers at once, all from `local_addr`,
    and compares what servers at *different IPs* saw: the same address is
    ENDPOINT_INDEPENDENT, different ones ENDPOINT_DEPENDENT, and fewer than
    two answers from different IPs is UNKNOWN (no verdict is not a verdict
    for either). Never raises for a server that fails; `protocol` defaults to
    "tcp" because the TCP mapping of the listening port is the one that
    matters for TCP hole punching, and `local_addr` should be that port.
    """
    if servers is None:
        servers = DEFAULT_TCP_SERVERS if protocol == "tcp" else DEFAULT_UDP_SERVERS
    results = await _query(list(servers)[:STUN_MAX_QUERIES], protocol,
                           local_addr)
    # One answer per server IP: two names for one machine are one vantage point.
    answers, seen = [], set()
    for result in results:
        if isinstance(result, Answer) and result.server_ip not in seen:
            seen.add(result.server_ip)
            answers.append(result)
    if len(answers) < 2:
        return MappingResult(UNKNOWN, answers)
    if len({a.address for a in answers}) == 1:
        return MappingResult(ENDPOINT_INDEPENDENT, answers)
    return MappingResult(ENDPOINT_DEPENDENT, answers)
