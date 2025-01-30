import os
from pathlib import Path

import pytest


@pytest.fixture(scope="function", autouse=True)
def prepare_env(tmp_path: Path):
    """
    Set environment variables appropriately for the unit tests.
    """
    starting_environ = dict(os.environ)

    os.environ["CAMRECORD_ROOT"] = str(tmp_path)
    os.environ["PYPS_ROOT"] = str(tmp_path)
    os.environ["IOC_DATA"] = str(tmp_path)

    yield

    os.environ.clear()
    os.environ.update(starting_environ)
