import socket
import subprocess
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
    def fake_get_commithost(hutch: str) -> str:
        return fake_commithost

    monkeypatch.setattr(commit, "get_commithost", fake_get_commithost)

    if local:
        # Force us to run locally by forcing get_commithost -> localhost
        fake_commithost = "localhost"
    else:
        # Force us to ssh to our same server by forcing get_commithost and gethostname
        fake_commithost = socket.gethostname()
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
    result = commit_config("pytest", msg)

    did_ssh = result.args[0] == "ssh"
    if local:
        assert not did_ssh, "Test writing error: local mode did an ssh"
    else:
        assert did_ssh, "Test writing error: nonlocal mode did not ssh"

    # Check the commit again
    info = subprocess.check_output(log_cmd, cwd=repo_dir, universal_newlines=True)
    assert msg in info
