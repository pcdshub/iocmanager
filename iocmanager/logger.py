"""
The logger module defines logging setup utilities and constants.
"""

import functools
import logging

SPAM_LEVEL = 5


def add_spam_level(lgr: logging.Logger):
    """
    Patch a "spam" function onto a logger instance.

    This function will log a message at the spam level,
    so that it won't appear in normal verbose mode but will appear
    in double verbose mode.
    """
    lgr.spam = functools.partial(lgr.log, SPAM_LEVEL)
