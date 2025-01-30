from pathlib import Path

from ..utils import readConfig, writeConfig
from . import CFG_FOLDER


def test_read_config():
    _, iocs, hosts, _ = readConfig(str(CFG_FOLDER / "example.cfg"))

    assert iocs == [
        {
            "id": "ioc-shouter",
            "host": "test-server1",
            "port": 30001,
            "dir": "iocs/shouter",
            "alias": "SHOUTER",
            "disable": False,
            "hard": False,
            "history": [],
            "cfgstat": 0,
            "rid": "ioc-shouter",
            "rdir": "iocs/shouter",
            "rhost": "test-server1",
            "rport": 30001,
            "newstyle": False,
            "pdir": "",
        },
        {
            "id": "ioc-spammer",
            "host": "test-server2",
            "port": 30002,
            "dir": "iocs/spammer",
            "history": ["iocs/old"],
            "disable": False,
            "hard": False,
            "alias": "",
            "cfgstat": 0,
            "rid": "ioc-spammer",
            "rdir": "iocs/spammer",
            "rhost": "test-server2",
            "rport": 30002,
            "newstyle": False,
            "pdir": "",
        },
    ]

    assert hosts == [
        "test-server1",
        "test-server2",
    ]


def test_write_config(tmp_path: Path):
    # Just write back our example config, it should be the same
    _, iocs, hosts, vars = readConfig(str(CFG_FOLDER / "example.cfg"))
    with open(tmp_path / "example.cfg", "w") as fd:
        writeConfig(hutch="unit_test", hostlist=hosts, cfglist=iocs, vars=vars, f=fd)

    with open(CFG_FOLDER / "example.cfg", "r") as fd:
        expected = fd.readlines()

    with open(tmp_path / "example.cfg", "r") as fd:
        actual = fd.readlines()

    assert actual == expected
