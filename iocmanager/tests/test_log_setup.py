import logging

import pytest

from ..log_setup import SPAM_LEVEL, log_spam


def test_add_spam_level(caplog: pytest.LogCaptureFixture):
    logger = logging.getLogger(f"{__file__}.test_add_spam_level")
    caplog.set_level(SPAM_LEVEL)
    caplog.clear()
    assert not caplog.get_records(when="call")
    log_spam(logger, "test")
    records = caplog.get_records(when="call")
    assert records
    assert records[0].message == "test"
