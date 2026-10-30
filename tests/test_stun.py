"""STUN client tests.

Nothing here talks to a public STUN server (the live tests at the end are
skipped unless P2P_NET_LIVE_STUN is set). A fake STUN server, over UDP and TCP
on loopback, plays the servers; "NAT" behaviour is scripted by having the
fake report an address of its choosing, so a real NAT is not involved.
"""

import asyncio
import os
import random
import socket
import struct
import time

import pytest

import stun
from stun import (
    ENDPOINT_DEPENDENT,
    ENDPOINT_INDEPENDENT,
    UNKNOWN,
    StunError,
    StunMalformed,
    detect_mapping,
    parse_binding_response,
    reusable_socket,
)

IP = "127.0.0.1"
COOKIE = 0x2112A442
TID = bytes(range(1, 13))


# --- Building STUN messages, independently of stun.py ---

def attr(attr_type, value):
    return struct.pack(">HH", attr_type, len(value)) + value + b"\0" * (-len(value) % 4)


def message(tid, *attrs, msg_type=0x0101, length=None, cookie=COOKIE):
    body = b"".join(attrs)
    return struct.pack(">HHI", msg_type, len(body) if length is None else length,
                       cookie) + tid + body


def xor_mapped(ip, port, tid):
    """XOR-MAPPED-ADDRESS, encoded by hand from RFC 8489 14.2."""
    packed = socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
    key = struct.pack(">I", COOKIE) + tid
    xored = bytes(b ^ k for b, k in zip(packed, key))
    family = 2 if ":" in ip else 1
    return attr(0x0020, bytes([0, family]) + struct.pack(">H", port ^ 0x2112) + xored)


def mapped(ip, port):
    packed = socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
    family = 2 if ":" in ip else 1
    return attr(0x0001, bytes([0, family]) + struct.pack(">H", port) + packed)


def error_code(code, reason="nope"):
    return attr(0x0009, bytes([0, 0, code // 100, code % 100]) + reason.encode())


def good(tid, ip="203.0.113.9", port=40000):
    return message(tid, xor_mapped(ip, port, tid))


# --- Parsing ---

def test_xor_mapped_address_ipv4_matches_the_rfc_5769_vector():
    """RFC 5769 2.2: the sample IPv4 response maps 192.0.2.1:32853."""
    tid = bytes.fromhex("b7e7a701bc34d686fa87dfae")
    value = bytes.fromhex("0001a147e112a643")
    data = message(tid, attr(0x0020, value))
    assert parse_binding_response(data, tid) == ("192.0.2.1", 32853)


def test_xor_mapped_address_ipv6_matches_the_rfc_5769_vector():
    """RFC 5769 2.3: the sample IPv6 response maps
    2001:db8:1234:5678:11:2233:4455:6677 port 32853 (the address is XORed
    with the cookie and the transaction id)."""
    tid = bytes.fromhex("b7e7a701bc34d686fa87dfae")
    value = bytes.fromhex("0002a1470113a9faa5d3f179bc25f4b5bed2b9d9")
    data = message(tid, attr(0x0020, value))
    assert parse_binding_response(data, tid) == (
        "2001:db8:1234:5678:11:2233:4455:6677", 32853)


@pytest.mark.parametrize("ip, port", [
    ("203.0.113.9", 40000), ("1.2.3.4", 1), ("255.255.254.1", 65535),
    ("2001:db8::7", 4242), ("fe80::1", 9),
])
def test_xor_decoding_round_trips(ip, port):
    assert parse_binding_response(good(TID, ip, port), TID) == (ip, port)


def test_mapped_address_is_the_fallback_and_xor_wins_when_both_are_there():
    assert parse_binding_response(
        message(TID, mapped("198.51.100.7", 5555)), TID) == ("198.51.100.7", 5555)
    both = message(TID, mapped("198.51.100.7", 5555),
                   xor_mapped("203.0.113.9", 40000, TID))
    assert parse_binding_response(both, TID) == ("203.0.113.9", 40000)


def test_unknown_optional_attributes_and_legacy_ones_are_skipped():
    data = message(TID, attr(0x8022, b"software"), attr(0x802C, b"x" * 8),
                   attr(0x0004, b"s" * 8), attr(0x0005, b"c" * 8),
                   xor_mapped("203.0.113.9", 40000, TID),
                   attr(0x8028, b"\0\0\0\0"))
    assert parse_binding_response(data, TID) == ("203.0.113.9", 40000)


def test_attribute_padding_is_skipped():
    """A 5-byte attribute is followed by 3 bytes of padding."""
    data = message(TID, attr(0x8022, b"12345"), xor_mapped("203.0.113.9", 7, TID))
    assert parse_binding_response(data, TID) == ("203.0.113.9", 7)


GOOD = good(TID)


@pytest.mark.parametrize("data", [
    b"",
    GOOD[:19],                                         # shorter than the header
    GOOD[:-1],                                         # length says more than there is
    GOOD + b"\0\0\0\0",                                # trailing bytes
    message(TID, length=3),                            # length not a multiple of 4
    message(TID, cookie=0x12345678),                   # RFC 3489-style, no cookie
    good(b"\xff" * 12),                                # someone else's transaction id
    bytes([0xC1]) + GOOD[1:],                          # top two bits set
    message(TID, msg_type=0x0001),                     # a request, not a response
    message(TID, msg_type=0x0011),                     # an indication
    b"GET / HTTP/1.1\r\n\r\n" + b"x" * 20,             # not STUN at all
])
def test_a_message_that_is_not_our_answer_is_malformed(data):
    with pytest.raises(StunMalformed):
        parse_binding_response(data, TID)


@pytest.mark.parametrize("data, text", [
    (message(TID, error_code(420, "Unknown Attribute"), msg_type=0x0111),
     "error 420"),
    (message(TID, msg_type=0x0111), "error response"),
    (message(TID), "no mapped address"),
    (message(TID, attr(0x8022, b"just software")), "no mapped address"),
    (message(TID, attr(0x0042, b"????"), xor_mapped("1.2.3.4", 5, TID)),
     "unknown comprehension-required attribute 0x0042"),
    (message(TID, struct.pack(">HH", 0x0020, 200) + b"\0" * 4),
     "past the end"),
    (message(TID, attr(0x0020, b"\0\x01\x00\x01\x01\x02\x03")), "family 1 and 3"),
    (message(TID, attr(0x0020, b"\0\x07\x00\x01\x01\x02\x03\x04")), "family 7"),
    (message(TID, attr(0x0020, b"\0\x01")), "shorter than 4"),
    (message(TID, xor_mapped("1.2.3.4", 0, TID)), "not a usable endpoint"),
    (message(TID, xor_mapped("0.0.0.0", 5, TID)), "not a usable endpoint"),
    (message(TID, xor_mapped("224.0.0.1", 5, TID)), "not a usable endpoint"),
    (message(TID, mapped("::", 5)), "not a usable endpoint"),
])
def test_an_answer_that_is_unusable_is_a_stun_error(data, text):
    with pytest.raises(StunError, match=text) as info:
        parse_binding_response(data, TID)
    assert not isinstance(info.value, StunMalformed)


def test_random_garbage_never_escapes_as_anything_but_a_stun_error():
    """Truncations, bit flips and random bytes of valid messages: whatever
    happens, the parser raises StunError (or returns an address), never
    IndexError, struct.error, ValueError and the like."""
    rng = random.Random(8489)
    samples = [good(TID), good(TID, "2001:db8::7", 99),
               message(TID, mapped("1.2.3.4", 5), attr(0x8022, b"abcde"))]
    for sample in samples:
        for cut in range(len(sample)):
            self_check(sample[:cut])
        for _ in range(300):
            data = bytearray(sample)
            for _ in range(rng.randint(1, 4)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            self_check(bytes(data))
    for _ in range(300):
        self_check(bytes(rng.randrange(256) for _ in range(rng.randint(0, 120))))
    # Random bodies behind a well-formed header reach the attribute parser.
    for _ in range(300):
        body = bytes(rng.randrange(256) for _ in range(4 * rng.randint(0, 20)))
        self_check(message(TID, body))


def self_check(data):
    try:
        address = parse_binding_response(data, TID)
    except StunError:
        return
    assert isinstance(address[0], str) and 0 < address[1] < 65536


# --- A fake STUN server over UDP and TCP ---

class FakeUdpServer(asyncio.DatagramProtocol):
    """Answers each datagram with what script(request, addr) returns (a list
    of datagrams, sent back to the sender); keeps the requests it saw."""

    def __init__(self, script):
        self.script = script
        self.requests = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.requests.append((data, addr))
        for reply in self.script(data, addr):
            self.transport.sendto(reply, addr)


async def start_udp(script, ip=IP):
    transport, server = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: FakeUdpServer(script), local_addr=(ip, 0))
    return transport, server, transport.get_extra_info("sockname")[1]


def tid_of(request):
    return request[8:20]


def report_source(request, addr):
    """The honest answer: the address the request came from."""
    return [good(tid_of(request), addr[0], addr[1])]


class FakeTcpServer:
    """A TCP STUN server: reads the 20-byte request, then runs
    script(request, writer) -> awaitable; closes the connection afterwards."""

    def __init__(self, script, ip=IP):
        self.script, self.ip = script, ip
        self.requests = []   # (request, client address)
        self.connections = 0
        self.handlers = set()

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._handle, self.ip, 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        for handler in self.handlers:   # e.g. one that is stalling on purpose
            handler.cancel()
        await asyncio.gather(*self.handlers, return_exceptions=True)
        await self.server.wait_closed()

    async def _handle(self, reader, writer):
        self.connections += 1
        self.handlers.add(asyncio.current_task())
        try:
            request = await reader.readexactly(20)
            self.requests.append((request, writer.get_extra_info("peername")))
            await self.script(request, writer)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    @property
    def address(self):
        return (self.ip, self.port)


async def tcp_report_source(request, writer):
    peer = writer.get_extra_info("peername")
    writer.write(good(tid_of(request), peer[0], peer[1]))
    await writer.drain()


def free_port():
    with socket.socket() as s:
        s.bind((IP, 0))
        return s.getsockname()[1]


@pytest.fixture
def fast_udp(monkeypatch):
    monkeypatch.setattr(stun, "STUN_UDP_RTO", 0.05)


# --- UDP ---

@pytest.mark.asyncio
async def test_udp_binding_request_is_well_formed_and_the_answer_decoded():
    transport, server, port = await start_udp(
        lambda req, addr: [good(tid_of(req), "203.0.113.9", 40000)])
    try:
        assert await stun.binding_request((IP, port), "udp") == ("203.0.113.9", 40000)
        request, _ = server.requests[0]
        message_type, length, cookie = struct.unpack(">HHI", request[:8])
        assert (message_type, length, cookie, len(request)) == (1, 0, COOKIE, 20)
        # A fresh random transaction id each time.
        await stun.binding_request((IP, port), "udp")
        assert tid_of(server.requests[0][0]) != tid_of(server.requests[1][0])
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_udp_ignores_wrong_transaction_ids_garbage_and_truncated_packets(
        fast_udp):
    """Off-path noise that arrives before the real answer is dropped without
    ending the transaction."""
    def script(req, addr):
        tid = tid_of(req)
        return [good(b"\x00" * 12, "6.6.6.6", 666),    # another transaction's
                b"\x01\x01\x00\x08",                   # truncated
                b"garbage" * 10,
                message(tid, length=4000),             # lies about its length
                bytes([0xff]) + good(tid)[1:],         # not a STUN message
                good(tid, "203.0.113.9", 40000)]       # the answer
    transport, server, port = await start_udp(script)
    try:
        assert await stun.binding_request((IP, port), "udp") == ("203.0.113.9", 40000)
        assert len(server.requests) == 1
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_udp_ignores_an_answer_from_the_wrong_source(fast_udp):
    """The reply has the right transaction id but comes from a socket the
    request was not sent to: not accepted, so the query times out."""
    spoofer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    spoofer.bind((IP, 0))

    def script(req, addr):
        spoofer.sendto(good(tid_of(req), "6.6.6.6", 666), addr)
        return []

    transport, server, port = await start_udp(script)
    try:
        with pytest.raises(StunError, match="no answer"):
            await stun.binding_request((IP, port), "udp")
    finally:
        transport.close()
        spoofer.close()


@pytest.mark.asyncio
async def test_udp_retransmits_with_a_doubling_timeout_then_gives_up(monkeypatch):
    monkeypatch.setattr(stun, "STUN_UDP_RTO", 0.1)
    transport, server, port = await start_udp(lambda req, addr: [])
    try:
        started = time.monotonic()
        with pytest.raises(StunError, match="after 3 requests"):
            await stun.binding_request((IP, port), "udp")
        elapsed = time.monotonic() - started
        assert len(server.requests) == stun.STUN_UDP_SENDS == 3
        assert 0.65 <= elapsed < 2.5   # 0.1 + 0.2 + 0.4 (+ scheduling)
        # The retransmissions are the same transaction.
        assert len({tid_of(r) for r, _ in server.requests}) == 1
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_udp_a_lost_request_is_retransmitted(fast_udp):
    seen = []

    def script(req, addr):
        seen.append(req)
        return [good(tid_of(req), "203.0.113.9", 40000)] if len(seen) == 3 else []

    transport, server, port = await start_udp(script)
    try:
        assert await stun.binding_request((IP, port), "udp") == ("203.0.113.9", 40000)
        assert len(seen) == 3
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_udp_an_error_response_ends_the_transaction_at_once(fast_udp):
    transport, server, port = await start_udp(
        lambda req, addr: [message(tid_of(req), error_code(420), msg_type=0x0111)])
    try:
        with pytest.raises(StunError, match="error 420"):
            await stun.binding_request((IP, port), "udp")
        assert len(server.requests) == 1
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_udp_unknown_required_attribute_fails_the_transaction(fast_udp):
    transport, server, port = await start_udp(
        lambda req, addr: [message(tid_of(req), attr(0x0099, b"1234"),
                                   xor_mapped("1.2.3.4", 5, tid_of(req)))])
    try:
        with pytest.raises(StunError, match="comprehension-required"):
            await stun.binding_request((IP, port), "udp")
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_udp_unresolvable_server_is_an_oserror():
    with pytest.raises(OSError):
        await stun.binding_request(("stun.invalid", 3478), "udp")


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["udp", "tcp"])
async def test_a_name_that_never_resolves_times_out(monkeypatch, protocol):
    monkeypatch.setattr(stun, "STUN_RESOLVE_TIMEOUT", 0.2)

    def slow_getaddrinfo(*args, **kwargs):
        time.sleep(1)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", slow_getaddrinfo)
    started = time.monotonic()
    with pytest.raises(StunError, match="resolving"):
        await stun.binding_request(("stun.example", 3478), protocol)
    assert time.monotonic() - started < 0.9


@pytest.mark.asyncio
async def test_udp_socket_is_closed_afterwards(monkeypatch, fast_udp):
    made = []
    real = stun.reusable_socket
    monkeypatch.setattr(stun, "reusable_socket",
                        lambda *a, **k: made.append(real(*a, **k)) or made[-1])
    transport, server, port = await start_udp(lambda req, addr: [])
    try:
        with pytest.raises(StunError):
            await stun.binding_request((IP, port), "udp")
        await asyncio.sleep(0.01)   # the transport closes its socket soon after
        assert made and all(s.fileno() == -1 for s in made)
    finally:
        transport.close()


# --- TCP ---

@pytest.mark.asyncio
async def test_tcp_binding_request_decodes_the_answer():
    async with FakeTcpServer(tcp_report_source) as server:
        address = await stun.binding_request(server.address, "tcp")
        assert address[0] == IP and address[1] > 0
        request, peer = server.requests[0]
        assert struct.unpack(">HHI", request[:8]) == (1, 0, COOKIE)
        assert address == (peer[0], peer[1])


@pytest.mark.asyncio
async def test_tcp_answer_in_single_bytes_is_reassembled():
    async def dribble(request, writer):
        for byte in good(tid_of(request), "203.0.113.9", 40000):
            writer.write(bytes([byte]))
            await writer.drain()
            await asyncio.sleep(0)
    async with FakeTcpServer(dribble) as server:
        assert await stun.binding_request(server.address, "tcp") == (
            "203.0.113.9", 40000)


@pytest.mark.asyncio
@pytest.mark.parametrize("reply, text", [
    (lambda tid: good(b"\x07" * 12), "transaction id"),
    (lambda tid: good(tid)[:25], "closed the connection"),
    (lambda tid: b"HTTP/1.1 400 Bad Request\r\n\r\n", "over the 1024-byte cap"),
    (lambda tid: b"\0" * 20, "not a STUN message"),
    (lambda tid: b"", "closed the connection"),
    (lambda tid: message(tid, error_code(500), msg_type=0x0111), "error 500"),
    (lambda tid: message(tid, attr(0x0099, b"1234")), "comprehension-required"),
    (lambda tid: message(tid), "no mapped address"),
])
async def test_tcp_bad_answers_are_stun_errors(reply, text):
    async def script(request, writer):
        writer.write(reply(tid_of(request)))
        await writer.drain()
    async with FakeTcpServer(script) as server:
        with pytest.raises(StunError, match=text):
            await stun.binding_request(server.address, "tcp")


@pytest.mark.asyncio
async def test_tcp_a_huge_declared_length_is_refused_without_reading_it():
    async def script(request, writer):
        writer.write(struct.pack(">HHI", 0x0101, 65532, COOKIE) + tid_of(request))
        await writer.drain()
        await asyncio.sleep(30)   # would hold the client if it waited for the body
    async with FakeTcpServer(script) as server:
        started = time.monotonic()
        with pytest.raises(StunError, match="over the 1024-byte cap"):
            await stun.binding_request(server.address, "tcp")
        assert time.monotonic() - started < 3


@pytest.mark.asyncio
async def test_tcp_a_silent_or_stalling_server_times_out(monkeypatch):
    monkeypatch.setattr(stun, "STUN_TCP_TIMEOUT", 0.3)

    async def silent(request, writer):
        await asyncio.sleep(30)

    async def stalls_mid_message(request, writer):
        writer.write(good(tid_of(request))[:30])
        await writer.drain()
        await asyncio.sleep(30)

    for script in (silent, stalls_mid_message):
        async with FakeTcpServer(script) as server:
            started = time.monotonic()
            with pytest.raises(StunError, match="no answer"):
                await stun.binding_request(server.address, "tcp")
            assert time.monotonic() - started < 3


@pytest.mark.asyncio
async def test_tcp_refused_connection_is_an_oserror():
    with pytest.raises(OSError):
        await stun.binding_request((IP, free_port()), "tcp")


@pytest.mark.asyncio
async def test_tcp_query_leaves_from_the_requested_port_even_when_a_listener_has_it():
    """The node's listener and the STUN query share the listening port; the
    server sees the query come from exactly that port."""
    port = free_port()
    listener = await asyncio.start_server(lambda r, w: None, IP, port,
                                          reuse_port=True)
    try:
        async with FakeTcpServer(tcp_report_source) as server:
            address = await stun.binding_request(server.address, "tcp", (IP, port))
            assert address == (IP, port)
            assert server.requests[0][1][1] == port
    finally:
        listener.close()
        await listener.wait_closed()


@pytest.mark.asyncio
async def test_tcp_sockets_are_closed_afterwards(monkeypatch):
    monkeypatch.setattr(stun, "STUN_TCP_TIMEOUT", 0.3)
    made = []
    real = stun.reusable_socket
    monkeypatch.setattr(stun, "reusable_socket",
                        lambda *a, **k: made.append(real(*a, **k)) or made[-1])

    async def silent(request, writer):
        await asyncio.sleep(30)

    async with FakeTcpServer(tcp_report_source) as ok, FakeTcpServer(silent) as hung:
        await stun.binding_request(ok.address, "tcp")
        with pytest.raises(StunError):
            await stun.binding_request(hung.address, "tcp")
        with pytest.raises(OSError):
            await stun.binding_request((IP, free_port()), "tcp")
    assert len(made) >= 3
    assert all(s.fileno() == -1 for s in made)


def test_protocol_must_be_udp_or_tcp():
    with pytest.raises(ValueError):
        asyncio.run(stun.binding_request((IP, 1), "sctp"))


# --- Mapping test ---

def shifted(by):
    """A fake server that sees the NAT map this flow to a different port (the
    behaviour of an endpoint-dependent NAT)."""
    return lambda req, addr: [good(tid_of(req), addr[0], addr[1] + by)]


async def tcp_shifted(request, writer):
    peer = writer.get_extra_info("peername")
    writer.write(good(tid_of(request), peer[0], peer[1] + 1))
    await writer.drain()


async def two_servers(protocol, script_a, script_b):
    """Two fake servers at different IPs (127.0.0.1 and 127.0.0.2). Returns
    (their (host, port) list, an async close function, each server's list of
    (request, client address))."""
    if protocol == "udp":
        ta, sa, pa = await start_udp(script_a, "127.0.0.1")
        tb, sb, pb = await start_udp(script_b, "127.0.0.2")

        async def close():
            ta.close()
            tb.close()
        return [("127.0.0.1", pa), ("127.0.0.2", pb)], close, [sa.requests, sb.requests]
    a = FakeTcpServer(script_a, "127.0.0.1")
    b = FakeTcpServer(script_b, "127.0.0.2")
    await a.__aenter__()
    await b.__aenter__()

    async def close():
        await a.__aexit__()
        await b.__aexit__()
    return [a.address, b.address], close, [a.requests, b.requests]


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["udp", "tcp"])
async def test_mapping_is_endpoint_independent_when_both_servers_see_the_same_port(
        protocol, fast_udp):
    script = report_source if protocol == "udp" else tcp_report_source
    servers, close, logs = await two_servers(protocol, script, script)
    try:
        local = free_port()
        result = await detect_mapping(servers, protocol, (IP, local))
        assert result.mapping == ENDPOINT_INDEPENDENT
        assert [a.address for a in result.answers] == [(IP, local)] * 2
        assert result.address == (IP, local)
        # Both queries left from the same local port: that is the whole test.
        assert [log[0][1][1] for log in logs] == [local, local]
    finally:
        await close()


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["udp", "tcp"])
async def test_mapping_is_endpoint_dependent_when_the_servers_disagree(
        protocol, fast_udp):
    """The second server sees a different port for the same local port, as it
    would behind a symmetric NAT."""
    script_b = shifted(1) if protocol == "udp" else tcp_shifted
    script_a = report_source if protocol == "udp" else tcp_report_source
    servers, close, logs = await two_servers(protocol, script_a, script_b)
    try:
        result = await detect_mapping(servers, protocol, (IP, free_port()))
        assert result.mapping == ENDPOINT_DEPENDENT
        assert len({a.address for a in result.answers}) == 2
    finally:
        await close()


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["udp", "tcp"])
async def test_mapping_with_a_port_chosen_by_the_os_still_shares_one_port(
        protocol, fast_udp):
    script = report_source if protocol == "udp" else tcp_report_source
    servers, close, logs = await two_servers(protocol, script, script)
    try:
        result = await detect_mapping(servers, protocol)   # local port 0
        assert result.mapping == ENDPOINT_INDEPENDENT
        assert logs[0][0][1][1] == logs[1][0][1][1] > 0
    finally:
        await close()


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["udp", "tcp"])
async def test_mapping_is_unknown_without_two_answers(protocol, monkeypatch,
                                                      fast_udp):
    monkeypatch.setattr(stun, "STUN_TCP_TIMEOUT", 0.3)
    monkeypatch.setattr(stun, "STUN_UDP_SENDS", 2)

    async def tcp_silent(request, writer):
        await asyncio.sleep(30)

    good_script = report_source if protocol == "udp" else tcp_report_source
    silent = (lambda req, addr: []) if protocol == "udp" else tcp_silent
    servers, close, _ = await two_servers(protocol, good_script, silent)
    try:
        result = await detect_mapping(servers, protocol, (IP, free_port()))
        assert result.mapping == UNKNOWN and len(result.answers) == 1
        # No servers at all, or a list of one, is unknown too.
        assert (await detect_mapping([], protocol)).mapping == UNKNOWN
        assert (await detect_mapping(servers[:1], protocol,
                                     (IP, free_port()))).mapping == UNKNOWN
    finally:
        await close()


@pytest.mark.asyncio
async def test_two_servers_at_one_ip_are_one_vantage_point():
    """Same IP, different ports: even if they reported different ports it
    would say nothing about the NAT, so there is no verdict."""
    async with FakeTcpServer(tcp_report_source) as a, \
            FakeTcpServer(tcp_shifted) as b:
        result = await detect_mapping([a.address, b.address], "tcp",
                                      (IP, free_port()))
        assert result.mapping == UNKNOWN and len(result.answers) == 1


@pytest.mark.asyncio
async def test_mapping_ignores_servers_that_lie_in_bad_ways(monkeypatch):
    """A server that answers with garbage counts as no answer; the others
    still give a verdict."""
    async def garbage(request, writer):
        writer.write(b"\xff" * 50)
        await writer.drain()

    servers = [FakeTcpServer(garbage, "127.0.0.3"),
               FakeTcpServer(tcp_report_source, "127.0.0.1"),
               FakeTcpServer(tcp_report_source, "127.0.0.2")]
    for s in servers:
        await s.__aenter__()
    try:
        result = await detect_mapping([s.address for s in servers], "tcp",
                                      (IP, free_port()))
        assert result.mapping == ENDPOINT_INDEPENDENT
        assert len(result.answers) == 2
    finally:
        for s in servers:
            await s.__aexit__()


@pytest.mark.asyncio
async def test_only_the_first_few_servers_are_queried(monkeypatch):
    monkeypatch.setattr(stun, "STUN_MAX_QUERIES", 2)
    servers = [FakeTcpServer(tcp_report_source, f"127.0.0.{i}") for i in (1, 2, 3)]
    for s in servers:
        await s.__aenter__()
    try:
        await detect_mapping([s.address for s in servers], "tcp",
                             (IP, free_port()))
        assert [s.connections for s in servers] == [1, 1, 0]
    finally:
        for s in servers:
            await s.__aexit__()


def test_default_servers_are_at_least_two_different_hosts():
    for servers in (stun.DEFAULT_UDP_SERVERS, stun.DEFAULT_TCP_SERVERS):
        assert len({host for host, _ in servers}) == len(servers) >= 2
    assert set(stun.DEFAULT_TCP_SERVERS) <= set(stun.DEFAULT_UDP_SERVERS) | {
        ("stun.signalwire.com", 3478), ("stun.voip.blackberry.com", 3478)}


def test_reusable_sockets_share_a_port():
    a = reusable_socket((IP, 0))
    b = reusable_socket((IP, a.getsockname()[1]))
    c = reusable_socket((IP, 0), socket.SOCK_DGRAM)
    d = reusable_socket((IP, c.getsockname()[1]), socket.SOCK_DGRAM)
    try:
        assert a.getsockname() == b.getsockname()
        assert c.getsockname() == d.getsockname()
        assert not a.getblocking()
    finally:
        for s in (a, b, c, d):
            s.close()


@pytest.mark.asyncio
async def test_a_tcp_connection_from_a_shared_port_is_reset_when_it_closes():
    """No TIME_WAIT entry may keep the shared port from connecting to the same
    address again, so closing resets the connection instead of ending it with
    a FIN (UDP sockets are left alone)."""
    seen = []

    async def handler(reader, writer):
        try:
            await reader.read()
            seen.append("eof")
        except ConnectionResetError:
            seen.append("reset")
        writer.close()

    server = await asyncio.start_server(handler, IP, 0)
    port = server.sockets[0].getsockname()[1]
    try:
        local = free_port()
        reader, writer = await stun.connect_from((IP, local), (IP, port), 2)
        sock = writer.get_extra_info("socket")
        assert struct.unpack("ii", sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER, 8)) == (1, 0)
        writer.close()
        await writer.wait_closed()
        for _ in range(100):
            if seen:
                break
            await asyncio.sleep(0.02)
        assert seen == ["reset"]
        # The same local port connects to the same address again at once.
        reader, writer = await stun.connect_from((IP, local), (IP, port), 2)
        writer.close()
    finally:
        server.close()
        await server.wait_closed()
    udp = reusable_socket((IP, 0), socket.SOCK_DGRAM)
    try:
        assert struct.unpack("ii", udp.getsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER, 8)) == (0, 0)
    finally:
        udp.close()


# --- Live tests: skipped unless P2P_NET_LIVE_STUN is set ---

live = pytest.mark.skipif(not os.environ.get("P2P_NET_LIVE_STUN"),
                          reason="set P2P_NET_LIVE_STUN=1 to query public "
                                 "STUN servers")


@live
@pytest.mark.asyncio
@pytest.mark.parametrize("protocol, servers", [
    ("udp", stun.DEFAULT_UDP_SERVERS), ("tcp", stun.DEFAULT_TCP_SERVERS)])
async def test_live_default_servers(protocol, servers, capsys):
    """Each default server, one at a time. The test needs at least two to
    answer (a server can be down); it prints who did."""
    results = await asyncio.gather(
        *(stun.binding_request(s, protocol) for s in servers),
        return_exceptions=True)
    with capsys.disabled():
        for server, result in zip(servers, results):
            print(f"\nlive {protocol} {server[0]}:{server[1]} -> "
                  f"{result if not isinstance(result, Exception) else repr(result)}",
                  end="")
    answered = [r for r in results if not isinstance(r, Exception)]
    assert len(answered) >= 2
    assert len({ip for ip, _ in answered}) == 1   # all see the same public IP


@live
@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["udp", "tcp"])
async def test_live_mapping_from_one_local_port(protocol, capsys):
    port = free_port()
    result = await detect_mapping(None, protocol, ("0.0.0.0", port))
    with capsys.disabled():
        print(f"\nlive {protocol} mapping from local port {port}: "
              f"{result.mapping}; " + ", ".join(
                  f"{a.server[0]} sees {a.address[0]}:{a.address[1]}"
                  for a in result.answers), end="")
    assert result.mapping in (ENDPOINT_INDEPENDENT, ENDPOINT_DEPENDENT)
    assert len(result.answers) >= 2
