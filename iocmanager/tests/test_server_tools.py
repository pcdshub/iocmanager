import pytest

from .. import server_tools
from ..server_tools import _netconfig, _sdfconfig, netconfig, reboot_server, sdfconfig

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


_example_sdfconfig_text = """
{"Hostname": "ctl-pytest-cam-01.pytest",
"Organization": "PYTEST",
"Subnet Name": "PYTEST1",
"IP": "10.0.0.1",
"MAC": "00:00:00:00:00:00",
"Hostgroup": "LinuxGroup",
"OS": "Test: Linux",
"Architecture": "x86_64",
"Owner": "People",
"PC": "PC99999",
"Power": "",
"Foreman Location": "SLAC-FM",
"Nlyte Location": "SLAC-NL",
"Cabinet": "Cab",
"Elevation": "42",
"Mounting Side": "Front",
"Type": "Specific Model Server",
"Serial Number": "N/A",
"Interfaces": [
{"Type": "primary",
"MAC": "00:00:00:00:00:00",
"IP": "10.0.0.1",
"Subnet Name": "PYTEST1",
"FQDN": "ctl-pytest-cam-01.pytest"},
{"Type": "bmc",
"MAC": "00:00:00:00:00:00",
"IP": "10.0.1.1",
"Subnet Name": "PYTEST2",
"FQDN": "ctl-pytest-cam-01b.pytest"},
{"Type": "interface",
"MAC": "00:00:00:00:00:00",
"IP": "10.0.2.1",
"Subnet Name": "PYTEST3",
"FQDN": "ctl-pytest-cam-01c.pytest"}]
}
"""


def test_sdfconfig_text_processing(monkeypatch: pytest.MonkeyPatch):
    def fake_sdfconfig(host: str, domain: str = "pytest"):
        return _example_sdfconfig_text

    monkeypatch.setattr(server_tools, "_sdfconfig", fake_sdfconfig)
    info = sdfconfig("ctl-pytest-cam-01", domain="pytest")
    assert info["Hostname"] == "ctl-pytest-cam-01.pytest"
    assert info["Subnet Name"] == "PYTEST1"
    assert info["PC"] == "PC99999"
    assert info["OS"] == "Test: Linux"
    assert info["MAC"] == "00:00:00:00:00:00"


def test_sdfconfig_call():
    host = "asdfsdf"
    assert _sdfconfig(host, "domain").strip() == f"sdfconfig view --json {host}.domain"


def test_reboot_server(capfd: pytest.CaptureFixture):
    # Fake reboot script tools/bin/psipmi just echoes our command
    host = "asdfsdfasdf"
    assert reboot_server(host)
    captured = capfd.readouterr()
    assert captured.out.strip() == f"psipmi {host} power cycle"
    assert captured.err == ""
