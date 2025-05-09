import pytest

from .. import server_tools
from ..server_tools import _netconfig, netconfig, rebootServer

_example_netconfig_text = """
        name: ctl-pytest-cam-01
        subnet: cds-pytest.pcdsn
        Ethernet Address: 00:00:00:00:00:00
        IP: 10.0.0.1
        PC#: 99999
        Location: SLAC
        Contact: uid=user,ou=People,dc=reg,o=slac
        Description: Ciara AMD7282
        DHCP parameters:
                filename "pxe/uefi/shim.efi";
        Puppet Classes:
"""


def test_netconfig_text_processing(monkeypatch: pytest.MonkeyPatch):
    def fake_netconfig(host: str):
        return _example_netconfig_text

    monkeypatch.setattr(server_tools, "_netconfig", fake_netconfig)
    info = netconfig("ctl-pytest-cam-01")
    assert info["name"] == "ctl-pytest-cam-01"
    assert info["subnet"] == "cds-pytest.pcdsn"
    assert info["pc#"] == "99999"


def test_netconfig_call():
    host = "asdfsdf"
    assert _netconfig(host).strip() == f"netconfig view {host}"


def test_reboot_server(capfd: pytest.CaptureFixture):
    # Fake reboot script tools/bin/psipmi just echoes our command
    host = "asdfsdfasdf"
    assert rebootServer(host)
    captured = capfd.readouterr()
    assert captured.out.strip() == f"psipmi {host} power cycle"
    assert captured.err == ""
