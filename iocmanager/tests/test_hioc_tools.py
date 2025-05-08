from __future__ import annotations

import telnetlib

import pytest

from .. import server_tools
from ..hioc_tools import (
    getHardIOCDir,
    rebootHIOC,
    restartHIOC,
)
from ..server_tools import netconfig


def test_get_hard_ioc_dir():
    assert getHardIOCDir("test-hioc") == "ioc/pytest/the-pytest-hiocs-folder/R1.0.0"
    assert getHardIOCDir("not-a-real-name") == "Unknown"


_hioc_netconfig_no_console_info = """
        name: ioc-pytest-hioc1
        subnet: cds-pytest.pcdsn
        Ethernet Address: 00:00:00:00:00:00
        IP: 10.0.0.1
        PC#: 99999
        Location: SLAC
        Contact: uid=user,ou=People,dc=reg,o=slac
        Description: RTEMS Gas Detector Crate
        DHCP parameters:
                filename "rtems-4.9.4/rtems.ralf";
        Puppet Classes:
"""

_hioc_netconfig_yes_console_info = """
        name: ioc-pytest-hioc2
        subnet: cds-pytest.pcdsn
        Ethernet Address: 00:00:00:00:00:00
        IP: 10.0.0.1
        PC#: 99999
        Location: SLAC
        Contact: uid=user,ou=People,dc=reg,o=slac
        Console Port DN: cn=port1,cn=digi-pytest-01,dc=cds-pytest.pcdsn,ou=Subnets,dc=reg,o=slac
        Description: VME High Voltage Crate in Pulse Lab
        DHCP parameters:
                filename "rtems-4.9.4/rtems.ralf";
        Puppet Classes:
"""  # noqa: E501


def test_restart_hioc(monkeypatch: pytest.MonkeyPatch):
    # This will be a bit silly, we'll mock netconfig and the Telnet class
    # and check that the results make sense
    def fake_netconfig(host: str):
        if host == "ioc-pytest-hioc1":
            return _hioc_netconfig_no_console_info
        elif host == "ioc-pytest-hioc2":
            return _hioc_netconfig_yes_console_info
        else:
            raise RuntimeError("Not a host")

    monkeypatch.setattr(server_tools, "_netconfig", fake_netconfig)

    class FakeTelnet:
        registry: list[FakeTelnet] = []

        def __init__(self, host: str, port: int, timeout: float):
            self.host = host
            self.port = port
            self.call_order = []
            self.registry.append(self)

        def write(self, msg: bytes):
            assert isinstance(msg, bytes), "Telnetlib requires bytes"
            self.call_order.append(("write", msg))

        def read_until(self, msg: bytes, count: int | None = None):
            assert isinstance(msg, bytes), "Telnetlib requires bytes"
            self.call_order.append(("read_until", msg))

        def close(self):
            self.call_order.append(("close",))

    monkeypatch.setattr(telnetlib, "Telnet", FakeTelnet)

    # Invalid host -> returns False I guess, netconfig should have no info for us
    assert not netconfig("asdfsdf")
    assert not restartHIOC("asdfsdf")

    # Host without port should also return False, even though netconfig doesn't error
    assert netconfig("ioc-pytest-hioc1")
    assert not restartHIOC("ioc-pytest-hioc1")

    # Host with proper info should create the correct Telnet and use it appropriately
    assert restartHIOC("ioc-pytest-hioc2")
    assert len(FakeTelnet.registry) == 1
    tn = FakeTelnet.registry[0]
    assert tn.host == "digi-pytest-01"
    assert tn.port == 2001
    # Yeah, this is silly, but I don't have a better idea right now.
    # Not robust to small changes in function implementation.
    assert tn.call_order == [
        ("write", b"\x0a"),  # Line feed
        ("read_until", b"> "),  # Wait for prompt
        ("write", b"exit\x0a"),  # Stop the process, line feed
        ("read_until", b"> "),  # Wait for prompt
        ("write", b"rtemsReboot()\x0a"),  # Force a reboot
        ("close",),  # End telnet connection
    ]


def test_reboot_hioc(capsys: pytest.CaptureFixture):
    # Fake reboot script tools/bin/power just echoes our command
    host = "asdfsdfasdf"
    assert rebootHIOC(host)
    captured = capsys.readouterr()
    assert captured.out.strip() == f"power {host} cycle"
    assert captured.err == ""
