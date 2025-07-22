from __future__ import annotations

import re

import pytest

from ..ioc_info import find_pv, get_base_name


@pytest.mark.parametrize(
    "ioc_name,pv_base,exception",
    [
        ("ioc1", "IOC:PYTEST:01", None),
        ("notanioc", "", OSError),
        ("iocbad", "", RuntimeError),
    ],
)
def test_get_base_name(
    ioc_name: str,
    pv_base: str,
    exception: type[Exception] | None,
):
    if exception is not None:
        with pytest.raises(exception):
            get_base_name(ioc_name)
    else:
        assert get_base_name(ioc_name) == pv_base


def test_find_pv():
    # See tests/ioc_data/ioc1/iocInfo/IOC.pvlist
    assert sorted(find_pv(re.compile("TST:.*"), "ioc1")) == [
        "TST:FLOAT",
        "TST:INT",
        "TST:STRING",
    ]
    assert len(find_pv(re.compile("IOC:PYTEST:.*"), "ioc1")) > 10
    assert not find_pv(re.compile(".*BIG:CAT.*"), "ioc1")
