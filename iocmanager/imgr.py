#!/usr/bin/env python
"""
The imgr module contains CLI-specific code for the imgr CLI tool.

imgr is a convenience cli script for accessing iocmanager's functions,
for example listing IOCs or moving them between hosts.
"""

import argparse
import os
import pwd
import socket
import sys

from psp.caput import caput

from . import procserv_tools as pt
from . import utils
from .config import (
    ConfigStat,
    IOCProc,
    check_auth,
    check_special,
    get_hutch_list,
    read_config,
    validate_config,
    write_config,
)
from .epics_paths import has_stcmd
from .ioc_info import get_base_name
from .procserv_tools import applyConfig, check_status, restartProc


def match_hutch(h, hlist):
    h = h.split("-")
    for i in range(min(2, len(h))):
        if h[i] in hlist:
            return h[i]
    return None


def get_hutch(ns):
    hlist = get_hutch_list()
    # First, take the --hutch specified on the command line.
    if ns.hutch is not None:
        if ns.hutch not in hlist:
            raise Exception("Nonexistent hutch %s" % ns.hutch)
        return ns.hutch
    # Second, try to match the current host.
    v = match_hutch(socket.gethostname(), hlist)
    # Finally, try to match the IOC name.
    if v is None and ns.ioc is not None:
        v = match_hutch(ns.ioc, hlist)
    return v


def usage():
    print("Usage: imgr IOCNAME [--hutch HUTCH] --status")
    print("       imgr IOCNAME [--hutch HUTCH] --info")
    print("       imgr IOCNAME [--hutch HUTCH] --connect")
    print("       imgr IOCNAME [--hutch HUTCH] --reboot soft")
    print("       imgr IOCNAME [--hutch HUTCH] --reboot hard")
    print("       imgr IOCNAME [--hutch HUTCH] --enable")
    print("       imgr IOCNAME [--hutch HUTCH] --disable")
    print("       imgr IOCNAME [--hutch HUTCH] --upgrade/dir RELEASE_DIR")
    print("       imgr IOCNAME [--hutch HUTCH] --move/loc HOST")
    print("       imgr IOCNAME [--hutch HUTCH] --move/loc HOST:PORT")
    print(
        "       imgr IOCNAME [--hutch HUTCH] --add --loc HOST:PORT --dir RELEASE_DIR "
        "--enable/disable"
    )
    print(
        "       imgr [--hutch HUTCH] --list [--host HOST] "
        "[--enabled_only|--disabled_only]"
    )
    print("")
    print("Note that '/' denotes a choice between two possible command names.")
    print("Also, --add, PORT may also be specified as 'open' or 'closed'.")
    sys.exit(1)


# Convert the port string to an integer.
# We need the host and the config list in case of 'open' or 'closed'.
def port_to_int(port, host, procs):
    if port != "closed" and port != "open":
        return int(port)
    plist = []
    for iocproc in procs:
        if iocproc.host == host:
            plist.append(int(iocproc.port))
    if port == "closed":
        r = list(range(30001, 39000))
    else:
        r = list(range(39100, 39200))
    for i in r:
        if i not in plist:
            print("Choosing %s port %d" % (port, i))
            return i
    raise ValueError("No available %s port?!?" % port)


def info(hutch, ioc, verbose):
    config = read_config(hutch)
    for iocproc in config.procs:
        if iocproc.name == ioc:
            d = check_status(iocproc.host, iocproc.port, ioc)
            if verbose:
                try:
                    if iocproc.disable:
                        if d["status"] == pt.STATUS_NOCONNECT:
                            d["status"] = "DISABLED"
                        elif d["status"] == pt.STATUS_RUNNING:
                            d["status"] = "DISABLED, BUT RUNNING?!?"
                except Exception:
                    pass
                try:
                    if iocproc.alias != "":
                        print("%s (%s):" % (ioc, iocproc.alias))
                    else:
                        print("%s:" % (ioc))
                except Exception:
                    print("%s:" % (ioc))
                print("    host  : %s" % iocproc.host)
                print("    port  : %s" % iocproc.port)
                print("    dir   : %s" % iocproc.path)
                print("    status: %s" % d["status"])
            else:
                print(d["status"])
            sys.exit(0)
    print("IOC %s not found in hutch %s!" % (ioc, hutch))
    sys.exit(1)


def soft_reboot(hutch, ioc):
    base = get_base_name(ioc)
    caput(base + ":SYSRESET", 1)
    sys.exit(0)


def hard_reboot(hutch, ioc):
    config = read_config(hutch)
    for iocproc in config.procs:
        if iocproc.name == ioc:
            restartProc(iocproc.host, iocproc.port)
            sys.exit(0)
    print("IOC %s not found in hutch %s!" % (ioc, hutch))
    sys.exit(1)


def do_connect(hutch, ioc):
    config = read_config(hutch)
    for iocproc in config.procs:
        if iocproc.name == ioc:
            os.execvp("telnet", ["telnet", iocproc.host, str(iocproc.port)])
            print("Exec failed?!?")
            sys.exit(1)
    print("IOC %s not found in hutch %s!" % (ioc, hutch))
    sys.exit(1)


def set_state(hutch, ioc, enable):
    if not check_special(ioc, hutch) and not check_auth(
        pwd.getpwuid(os.getuid())[0], hutch
    ):
        print("Not authorized!")
        sys.exit(1)
    config = read_config(hutch)
    try:
        utils.COMMITHOST = config.commithost
    except Exception:
        pass
    for iocproc in config.procs:
        if iocproc.name == ioc:
            iocproc.disable = not enable
            write_config(hutch, config)
            applyConfig(hutch, None, ioc)
            sys.exit(0)
    print("IOC %s not found in hutch %s!" % (ioc, hutch))
    sys.exit(1)


def add(hutch, ioc, version, hostport, disable):
    if not check_auth(pwd.getpwuid(os.getuid())[0], hutch):
        print("Not authorized!")
        sys.exit(1)
    if not has_stcmd(version, ioc):
        print("%s does not have an st.cmd for %s!" % (version, ioc))
        sys.exit(1)
    config = read_config(hutch)
    try:
        utils.COMMITHOST = config.commithost
    except Exception:
        pass
    hp = hostport.split(":")
    host = hp[0].lower()
    port = hp[1].lower()
    if len(hp) != 2:
        print("Must specify host and port!")
        sys.exit(1)
    for iocproc in config.procs:
        if iocproc["id"] == ioc:
            print("IOC %s already exists in hutch %s!" % (ioc, hutch))
            sys.exit(1)
    port = port_to_int(port, host, config.procs)
    config.procs.append(
        IOCProc(
            name=ioc,
            port=port,
            host=host,
            path=version,
            alias="",
            status=ConfigStat.ADDED,
            disable=disable,
            cmd="",
            history=[],
        )
    )
    if host not in config.hosts:
        config.hosts.append(host)
    write_config(hutch, config)
    applyConfig(hutch, None, ioc)
    sys.exit(0)


def upgrade(hutch, ioc, version):
    # check if the version change is permissible
    allow_toggle = check_special(ioc, hutch, version)

    # check if user is authed to do any upgrade
    allow_upgrade = check_auth(pwd.getpwuid(os.getuid())[0], hutch)

    if not (allow_upgrade or allow_toggle):
        print("Not authorized!")
        sys.exit(1)
    if not has_stcmd(version, ioc):
        print("%s does not have an st.cmd for %s!" % (version, ioc))
        sys.exit(1)
    config = read_config(hutch)
    try:
        utils.COMMITHOST = config.commithost
    except Exception:
        pass
    for iocproc in config.procs:
        if iocproc.name == ioc:
            iocproc.path = version
            write_config(hutch, config)
            applyConfig(hutch, None, ioc)
            sys.exit(0)
    print("IOC %s not found in hutch %s!" % (ioc, hutch))
    sys.exit(1)


def move(hutch, ioc, hostport):
    if not check_auth(pwd.getpwuid(os.getuid())[0], hutch):
        print("Not authorized!")
        sys.exit(1)
    config = read_config(hutch)
    try:
        utils.COMMITHOST = config.commithost
    except Exception:
        pass
    for iocproc in config.procs:
        if iocproc.name == ioc:
            hp = hostport.split(":")
            iocproc.host = hp[0]
            if len(hp) > 1:
                iocproc["newport"] = port_to_int(hp[1], hp[0], config.procs)
            if not validate_config(config.procs):
                print(
                    "Port conflict when moving %s to %s, not moved!" % (ioc, hostport)
                )
                sys.exit(1)
            write_config(hutch, config)
            applyConfig(hutch, None, ioc)
            sys.exit(0)
    print("IOC %s not found in hutch %s!" % (ioc, hutch))
    sys.exit(1)


def do_list(hutch, ns):
    config = read_config(hutch)
    h = ns.host
    show_disabled = not ns.enabled_only
    show_enabled = not ns.disabled_only
    for iocproc in config.procs:
        if h is not None and iocproc.host != h:
            continue
        if not (show_disabled if iocproc.disable else show_enabled):
            continue
        if iocproc.alias != "":
            print(("%s (%s)" % (iocproc.name, iocproc.alias)))
        else:
            print(("%s" % iocproc.name))
    sys.exit(0)


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(prog="imgr")
        parser.add_argument("ioc", nargs="?")
        parser.add_argument("--status", action="store_true")
        parser.add_argument("--info", action="store_true")
        parser.add_argument("--connect", action="store_true")
        parser.add_argument("--reboot")
        parser.add_argument("--disable", action="store_true")
        parser.add_argument("--enable", action="store_true")
        parser.add_argument("--upgrade")
        parser.add_argument("--dir")
        parser.add_argument("--move")
        parser.add_argument("--loc")
        parser.add_argument("--hutch")
        parser.add_argument("--list", action="store_true")
        parser.add_argument("--disabled_only", action="store_true")
        parser.add_argument("--enabled_only", action="store_true")
        parser.add_argument("--add", action="store_true")
        parser.add_argument("--host")
        ns = parser.parse_args(sys.argv[1:])
    except Exception:
        usage()
    hutch = get_hutch(ns)
    if hutch is None:
        usage()
    if ns.list:
        do_list(hutch, ns)
    if ns.ioc is None:
        usage()
    if ns.status or ns.info:
        info(hutch, ns.ioc, ns.info)
    elif ns.connect:
        do_connect(hutch, ns.ioc)
    elif ns.reboot is not None:
        if ns.reboot == "hard":
            hard_reboot(hutch, ns.ioc)
        elif ns.reboot == "soft":
            soft_reboot(hutch, ns.ioc)
        else:
            usage()
    elif ns.add:
        if ns.dir is None or ns.loc is None or (ns.disable and ns.enable):
            usage()
        add(hutch, ns.ioc, ns.dir, ns.loc, ns.disable)
    elif ns.disable and ns.enable:
        usage()
    elif ns.disable or ns.enable:
        set_state(hutch, ns.ioc, ns.enable)
    elif ns.upgrade is not None or ns.dir is not None:
        upgrade(hutch, ns.ioc, ns.dir if ns.upgrade is None else ns.upgrade)
    elif ns.move is not None or ns.loc is not None:
        move(hutch, ns.ioc, ns.loc if ns.move is None else ns.move)
    else:
        usage()
    sys.exit(0)
