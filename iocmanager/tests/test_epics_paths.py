import os
from itertools import product

import pytest

from .. import env_paths, epics_paths
from ..epics_paths import epics_readlines, get_parent, has_stcmd, normalize_path
from . import IOC_FOLDER, TESTS_FOLDER

# Possible pieces to normalize
test_normalize_prefix = ("", "../", "../../", "EPICS_SITE_TOP")
test_normalize_iocdir = "ioc/common/ci/R1.0.0/"
test_normalize_extra_parts = (
    "",
    "iocBoot/",
    "build/iocBoot/",
    "children/build/iocBoot/",
)
test_normalize_iocnames = ("fake_ioc1", "fake_ioc2")

# Build all the variants
test_fix_dir_params = []
for prefix in test_normalize_prefix:
    for ext in test_normalize_extra_parts:
        for ioc in test_normalize_iocnames:
            test_fix_dir_params.append(
                (f"{prefix}{test_normalize_iocdir}{ext}{ioc}", ioc)
            )


@pytest.mark.parametrize("ioc_dir,ioc_name", test_fix_dir_params)
def test_normalize_path(ioc_dir: str, ioc_name: str):
    ioc_dir = ioc_dir.replace("EPICS_SITE_TOP", "")
    ioc_dir = os.path.join(env_paths.EPICS_SITE_TOP, ioc_dir)
    if "iocBoot" in ioc_dir:
        answer = test_normalize_iocdir.removesuffix("/")
    else:
        # Implementation does no special suffix removal if iocBoot isn't here
        # So the trailing ioc dir remains, but the other processing is done
        answer = f"{test_normalize_iocdir}{ioc_name}"
    assert normalize_path(ioc_dir, ioc_name) == answer


def test_normalize_path_absdir():
    assert normalize_path("/some/full/path", "iocname") == "/some/full/path"


dname_opts = (
    "iocs/common_ioc",
    "iocs/common_ioc/children",
    "iocs/common_ioc/children/build",
    "iocs/common_ioc/children/build/iocBoot/child_ioc",
)
bopts = (True, False)


@pytest.mark.parametrize(
    "dirname,abs_path",
    list(product(dname_opts, bopts)),
)
def test_has_stcmd(dirname: str, abs_path: bool):
    # See tests/iocs, valid dirs have st.cmd
    # Need to cover every case in utils.stpaths:
    # "%s/children/build/iocBoot/%s/st.cmd"
    # "%s/build/iocBoot/%s/st.cmd"
    # "%s/iocBoot/%s/st.cmd"
    # Plus directory/st.cmd
    # Also needs to cover abs paths and relative paths to
    # EPICS_SITE_TOP (Which is set to the tests folder)
    if abs_path:
        dirname = str(TESTS_FOLDER / dirname)
    assert has_stcmd(dirname, "child_ioc")


def test_has_stcmd_neg():
    assert not has_stcmd(str(TESTS_FOLDER), "child_ioc")


def test_get_parent(monkeypatch: pytest.MonkeyPatch):
    # NOTE: skip testing $$PATH, which is an unused feature

    # Normal template IOC
    assert (
        get_parent(str(IOC_FOLDER / "templated_ioc"), "hutch_ioc")
        == "/some/absolute/path"
    )

    # Typical common/children structure
    common_path = IOC_FOLDER / "common_ioc"
    assert get_parent(str(common_path), "child_ioc") == str(
        IOC_FOLDER.relative_to(TESTS_FOLDER) / "common_ioc"
    )

    # A real file without this pattern
    name1 = "malformed_ioc"
    assert (common_path / "children" / f"{name1}.cfg").exists()
    assert get_parent(str(common_path), name1) == ""

    # Not a real file
    name2 = "asdfasefef"
    assert not (common_path / "children" / f"{name2}.cfg").exists()
    with pytest.raises(OSError):
        get_parent(str(common_path), name2)

    # Set up fake epics_readlines for more specific regex testing
    release_line = ""

    def fake_epics_readlines(*args, **kwargs):
        return [release_line + "\n"]

    monkeypatch.setattr(epics_paths, "epics_readlines", fake_epics_readlines)

    # Variants to exercise each regex in the original implementation
    answer = "/true/parent/path"
    sp_opts = ("", " ", "\t")
    rel_ops = ("RELEASE",)
    eq_opts = ("=", " ")
    answer_opts = (answer, f'"{answer}"', f"'{answer}'")

    lines = product(sp_opts, rel_ops, sp_opts, eq_opts, sp_opts, answer_opts, sp_opts)

    for trial_parts in lines:
        release_line = "".join(trial_parts)
        assert (
            get_parent("/some/dir", "some_ioc") == answer
        ), f"Issue with {release_line}"


def test_epics_readlines():
    # This is pretty dumb but whatever
    my_lines = [
        "hey\n",
        "this is an epics thing\n",
        "I guess\n",
    ]

    assert epics_readlines("iocs/test_read_all.txt") == my_lines
    assert epics_readlines(str(TESTS_FOLDER / "iocs" / "test_read_all.txt")) == my_lines
    with pytest.raises(OSError):
        epics_readlines("defo_not_a_path")
