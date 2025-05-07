import logging

import pytest

from ..logger import SPAM_LEVEL, add_spam_level


def test_add_spam_level(caplog: pytest.LogCaptureFixture):
    logger = logging.getLogger(f"{__file__}.test_add_spam_level")
    assert not hasattr(logger, "spam")
    add_spam_level(logger)
    caplog.set_level(SPAM_LEVEL)
    caplog.clear()
    assert not caplog.get_records(when="call")
    logger.spam("test")
    records = caplog.get_records(when="call")
    assert records
    assert records[0].message == "test"
