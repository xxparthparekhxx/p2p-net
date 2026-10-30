import asyncio
import os
import socket
import subprocess
import sys
import threading

import pytest

import upnp
from kademlia_dht import connect, read_frame, write_frame
from p2p_node import P2PNode, is_loopback
from upnp import UPnPMapping

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAN_ADDRESS = "192.168.1.50"
EXTERNAL_IP = "203.0.113.7"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeMiniupnpc:
    """Stands in for the miniupnpc module, with a router that can be told to
    misbehave. Records what the code under test asked of it."""

    def __init__(self, no_igd=False, add_result=True, add_error=None,
                 external_ip_error=None, delete_result=True,
                 delete_error=None, hold=None):
        self.no_igd = no_igd
        self.add_result = add_result
        self.add_error = add_error
        self.external_ip_error = external_ip_error
        self.delete_result = delete_result
        self.delete_error = delete_error
        # A threading.Event the router's first answer (discover) waits for.
        self.hold = hold
        self.mappings = {}   # (port, protocol) -> (host, internal port, desc)
        self.deleted = []
        self.instances = 0
        self.threads = []    # the thread each router call ran in

    def UPnP(self):
        self.instances += 1
        return FakeUPnP(self)


class FakeUPnP:
    def __init__(self, router):
        self.router = router
        self.lanaddr = LAN_ADDRESS

    def discover(self):
        self.router.threads.append(threading.current_thread())
        if self.router.hold is not None:
            # Bounded, so a test that forgets to release it can't hang.
            self.router.hold.wait(5)
        return 1

    def selectigd(self):
        if self.router.no_igd:
            raise Exception("No IGD UPnP Device found on the network !")

    def addportmapping(self, external_port, protocol, internal_host,
                       internal_port, description, remote_host):
        if self.router.add_error is not None:
            raise self.router.add_error
        if not self.router.add_result:
            return False
        self.router.mappings[(external_port, protocol)] = (
            internal_host, internal_port, description)
        return True

    def externalipaddress(self):
        if self.router.external_ip_error is not None:
            raise self.router.external_ip_error
        return EXTERNAL_IP

    def deleteportmapping(self, external_port, protocol):
        self.router.threads.append(threading.current_thread())
        if self.router.delete_error is not None:
            raise self.router.delete_error
        self.router.deleted.append((external_port, protocol))
        if self.router.delete_result:
            self.router.mappings.pop((external_port, protocol), None)
        return self.router.delete_result


def install(monkeypatch, **kwargs) -> FakeMiniupnpc:
    router = FakeMiniupnpc(**kwargs)
    monkeypatch.setattr(upnp, "miniupnpc", router)
    return router


def new_node(tmp_path, ip="0.0.0.0", **kwargs):
    return P2PNode(ip, free_port(), key_path=str(tmp_path / "node.key"),
                   **kwargs)


async def ping(node):
    """PING the node over TCP, the way any peer would."""
    reader, writer = await connect("127.0.0.1", node.port)
    try:
        await write_frame(writer, b"PING")
        return await asyncio.wait_for(read_frame(reader), 5)
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_start_maps_the_listening_port_and_stop_removes_it(
        tmp_path, monkeypatch):
    router = install(monkeypatch)
    node = new_node(tmp_path)
    await node.start()
    try:
        assert router.mappings == {
            (node.port, "TCP"): (LAN_ADDRESS, node.port, "p2p-net")}
        assert node.upnp.external_ip == EXTERNAL_IP
        assert await ping(node) == b"PONG"
    finally:
        await node.stop()
    assert router.mappings == {}
    assert router.deleted == [(node.port, "TCP")]
    assert node.upnp is None
    await node.stop()  # a second stop does not ask the router again
    assert router.deleted == [(node.port, "TCP")]


@pytest.mark.asyncio
async def test_the_router_is_asked_from_a_worker_thread(tmp_path, monkeypatch):
    """miniupnpc blocks; it must not run on the event loop's thread."""
    router = install(monkeypatch)
    node = new_node(tmp_path)
    await node.start()
    await node.stop()
    assert len(router.threads) == 2  # the discovery and the removal
    assert threading.current_thread() not in router.threads


@pytest.mark.asyncio
async def test_run_removes_the_mapping_when_cancelled(tmp_path, monkeypatch):
    router = install(monkeypatch)
    node = new_node(tmp_path)
    await node.start()
    task = asyncio.create_task(node.run())
    await asyncio.sleep(0.05)
    assert router.mappings
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert router.mappings == {}


@pytest.mark.asyncio
async def test_without_miniupnpc_the_node_just_starts(tmp_path):
    # conftest leaves upnp.miniupnpc as None, as when it isn't installed.
    node = new_node(tmp_path)
    await node.start()
    try:
        assert node.upnp.external_ip is None
        assert await ping(node) == b"PONG"
    finally:
        await node.stop()


@pytest.mark.parametrize("trouble, message", [
    ({"no_igd": True}, "No IGD"),
    ({"add_result": False}, "refused"),
    ({"add_error": Exception("ConflictInMappingEntry")}, "ConflictIn"),
])
@pytest.mark.asyncio
async def test_a_router_that_will_not_map_is_not_fatal(
        tmp_path, monkeypatch, capsys, trouble, message):
    router = install(monkeypatch, **trouble)
    node = new_node(tmp_path)
    await node.start()
    try:
        assert router.mappings == {}
        assert message in capsys.readouterr().out
        assert await ping(node) == b"PONG"
    finally:
        await node.stop()
    assert router.deleted == []  # there was nothing to remove


@pytest.mark.asyncio
async def test_a_mapping_without_a_known_external_address_still_counts(
        tmp_path, monkeypatch):
    router = install(monkeypatch, external_ip_error=Exception("no ip"))
    node = new_node(tmp_path)
    await node.start()
    try:
        assert (node.port, "TCP") in router.mappings
        assert node.upnp.external_ip is None
    finally:
        await node.stop()
    assert router.mappings == {}


@pytest.mark.parametrize("trouble", [
    {"delete_error": Exception("SOAP request failed")},
    {"delete_result": False},
])
@pytest.mark.asyncio
async def test_a_failed_removal_does_not_stop_the_shutdown(
        tmp_path, monkeypatch, trouble):
    install(monkeypatch, **trouble)
    node = new_node(tmp_path)
    await node.start()
    await node.stop()  # does not raise
    assert not node.server.is_serving()


@pytest.mark.asyncio
async def test_loopback_nodes_and_upnp_false_do_not_ask_the_router(
        tmp_path, monkeypatch):
    router = install(monkeypatch)
    loopback = new_node(tmp_path, ip="127.0.0.1")
    await loopback.start()
    await loopback.stop()
    disabled = new_node(tmp_path, upnp=False)
    await disabled.start()
    await disabled.stop()
    assert router.instances == 0
    assert loopback.upnp is None and disabled.upnp is None


def test_is_loopback():
    assert is_loopback("127.0.0.1") and is_loopback("127.0.0.2")
    assert is_loopback("::1")
    assert not is_loopback("0.0.0.0")
    assert not is_loopback("192.168.1.5")
    assert not is_loopback("203.0.113.7")
    assert not is_loopback("localhost")  # a name, not an address


@pytest.mark.asyncio
async def test_a_router_that_never_answers_does_not_hold_up_the_node(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(upnp, "UPNP_TIMEOUT", 0.3)
    hold = threading.Event()
    install(monkeypatch, hold=hold)
    node = new_node(tmp_path)
    try:
        await asyncio.wait_for(node.start(), 3)
        assert "did not answer" in capsys.readouterr().out
        assert await ping(node) == b"PONG"
        await asyncio.wait_for(node.stop(), 3)  # bounded as well
    finally:
        hold.set()  # let the worker thread finish


async def settle(predicate, tries=200):
    for _ in range(tries):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition never became true")


@pytest.mark.asyncio
async def test_a_mapping_that_arrives_before_close_gives_up_is_removed(
        tmp_path, monkeypatch):
    monkeypatch.setattr(upnp, "UPNP_TIMEOUT", 0.5)
    hold = threading.Event()
    router = install(monkeypatch, hold=hold)
    node = new_node(tmp_path)
    await node.start()          # gives up waiting after 0.5 s
    assert router.mappings == {}
    hold.set()                  # the router answers late
    await node.stop()           # waits for it, then removes the mapping
    assert router.mappings == {}
    assert router.deleted == [(node.port, "TCP")]


@pytest.mark.asyncio
async def test_a_mapping_that_arrives_after_close_gave_up_is_removed_too(
        tmp_path, monkeypatch):
    monkeypatch.setattr(upnp, "UPNP_TIMEOUT", 0.2)
    hold = threading.Event()
    router = install(monkeypatch, hold=hold)
    node = new_node(tmp_path)
    await node.start()
    await node.stop()           # gives up on the router as well
    assert router.mappings == {} and router.deleted == []
    hold.set()                  # now the router answers
    await settle(lambda: router.deleted)
    assert router.mappings == {}
    assert router.deleted == [(node.port, "TCP")]


@pytest.mark.asyncio
async def test_a_removal_the_router_never_answers_is_bounded(
        tmp_path, monkeypatch):
    install(monkeypatch)
    node = new_node(tmp_path)
    await node.start()
    release = threading.Event()

    def stuck(port, protocol):
        release.wait(5)
        return True

    monkeypatch.setattr(upnp, "UPNP_TIMEOUT", 0.2)
    node.upnp._upnp.deleteportmapping = stuck
    try:
        await asyncio.wait_for(node.stop(), 3)
    finally:
        release.set()
    assert not node.server.is_serving()
    assert node.upnp is None


def run_python(code):
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True,
                          capture_output=True, text=True, timeout=60).stdout


def test_the_module_imports_without_miniupnpc():
    out = run_python(
        "import sys; sys.modules['miniupnpc'] = None\n"  # makes the import fail
        "import upnp, p2p_node\n"
        "print(upnp.miniupnpc)")
    assert out.strip() == "None"


def test_the_module_uses_miniupnpc_when_it_is_installed():
    out = run_python(
        "import sys, types\n"
        "fake = types.ModuleType('miniupnpc'); sys.modules['miniupnpc'] = fake\n"
        "import upnp\n"
        "print(upnp.miniupnpc is fake)")
    assert out.strip() == "True"


@pytest.mark.asyncio
async def test_open_returns_false_without_miniupnpc():
    mapping = UPnPMapping(9000)
    assert await mapping.open() is False
    await mapping.close()  # nothing to remove
