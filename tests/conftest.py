import signal

import pytest

import upnp


@pytest.fixture(autouse=True)
def isolated_key_dir(tmp_path, monkeypatch):
    """Nodes persist their signing key (and P2PNode its owner pins); keep
    every such file (and any ~ expansion) inside this test's tmp_path, never
    the real home dir."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("P2P_NET_KEY_DIR", str(tmp_path / "keys"))


@pytest.fixture(autouse=True)
def no_real_upnp(monkeypatch):
    """A machine that has miniupnpc installed must not have the tests talk
    to its router; tests that cover UPnP install a fake instead."""
    monkeypatch.setattr(upnp, "miniupnpc", None)


TEST_TIMEOUT = 30


@pytest.fixture(autouse=True)
def hung_test_fails(request):
    """A test that hangs (a bug that leaves it waiting on a socket nothing
    will close) fails after TEST_TIMEOUT seconds instead of stalling the
    run. Unix only; the alarm raises inside the event loop's wait."""
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def expired(signum, frame):
        raise TimeoutError(f"{request.node.name} did not finish in "
                           f"{TEST_TIMEOUT}s: hung")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(TEST_TIMEOUT)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
