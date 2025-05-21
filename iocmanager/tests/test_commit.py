import io
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from .. import commit
from ..commit import commit_config, get_commithost
from ..config import DEFAULT_COMMITHOST, read_config, write_config


def test_get_commithost():
    assert get_commithost("pytest") == "localhost"
    assert get_commithost("second_hutch") == DEFAULT_COMMITHOST


@pytest.mark.parametrize("local", (True, False))
def test_commit_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, local: bool):
    if local:
        # Force us to run locally by forcing get_commithost -> localhost
        monkeypatch.setattr(commit, "get_commithost", lambda: "localhost")
    else:
        # Force us to ssh to our same server by forcing get_commithost and gethostname
        pytest.xfail("Having trouble figuring out kerberos auth")
        monkeypatch.setattr(commit, "get_commithost", lambda: socket.gethostname())
        monkeypatch.setattr(commit, "gethostname", lambda: "localhost")

    repo_dir = tmp_path / "pyps_root" / "config" / "pytest"
    # Set up a git repo
    subprocess.run(["git", "init"], cwd=repo_dir, universal_newlines=True)

    # Commit the file
    msg = "initial commit"
    subprocess.run(
        ["git", "add", "iocmanager.cfg"], cwd=repo_dir, universal_newlines=True
    )
    subprocess.run(["git", "commit", "-m", msg], cwd=repo_dir, universal_newlines=True)

    # Check that we have a commit
    log_cmd = ["git", "log", "-n", "1", "--oneline"]
    info = subprocess.check_output(log_cmd, cwd=repo_dir, universal_newlines=True)
    assert msg in info

    # Typical read/write operation
    config = read_config("pytest")
    config.hosts.append("newhost")
    write_config("pytest", config)

    # Commit the file with our function to test
    msg = "added newhost"
    with monkeypatch.context() as mp:
        # fabric and pytest do not play nice with each other unless you disable stdin
        mp.setattr(sys, "stdin", io.StringIO(""))
        result = commit_config("pytest", msg)

    did_connect = hasattr(result, "connection")
    if local:
        assert not did_connect, "Test writing error: local mode did an ssh"
    else:
        assert did_connect, "Test writing error: nonlocal mode did not ssh"

    # Check the commit again
    info = subprocess.check_output(log_cmd, cwd=repo_dir, universal_newlines=True)
    assert msg in info
