#!/usr/bin/bash
# Subprocess target for iocmanager.commit.commit_config
# This is easier than doing commands all in one line in the python file
set -e
set -x
config_file="${1}"
comment="${2}"

cd "$(dirname "${config_file}")"
umask 2
git commit -m "${comment}" "${config_file}"
