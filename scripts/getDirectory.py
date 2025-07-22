"""
Backcompat script for dealing with old py2 iocmanager's startProc.

Can remove when all instances of the py2 iocmanager are gone.
"""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent

args = ["python", "-m", "iocmanager.scripts.get_directory"] + sys.argv[1:]

subprocess.run(args, cwd=str(REPO_ROOT))

