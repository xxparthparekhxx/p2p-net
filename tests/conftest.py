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
