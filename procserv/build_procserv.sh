#!/usr/bin/bash
# Helper script for building procServ, which is used very much in iocmanager.
# This will do the following:
# - Download the procServ release at a specific tag
# - Check the sha256 sum
# - Untar the tarball
# - configure and make
# - create a relocatable "bin" directory to deploy to e.g. /cds/group/pcds/package
# - expected structure is e.g. $EPICS_HOST_ARCH/bin/procServ
set -e
VERSION=2.8.0-1.2.0
SHA=904374fb696e575da6057d729b9e1b683d6f2b28d57aa7f49c30aabc7b35f4eb

THIS_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
cd "${THIS_DIR}"

if [ -z "${EPICS_HOST_ARCH}" ]; then
    EPICS_HOST_ARCH="unknown"
fi

mkdir -p build/"${EPICS_HOST_ARCH}"/src
cd build

TARBALL="procServ-${VERSION}.tar.gz"
if [ -f "${TARBALL}" ]; then
    echo "Found tarball, skip download"
else
    echo "No tarball, start download"
    curl -LJ "https://github.com/slac-epics/procServ/archive/refs/tags/R${VERSION}.tar.gz" > "${TARBALL}"
fi

UNTAR_DIR="${EPICS_HOST_ARCH}/src"
if [ -f "${UNTAR_DIR}/README.md" ]; then
    echo "Already untarred"
else
    echo "Checking SHA"
    if [ "$(sha256sum "procServ-${VERSION}.tar.gz" | cut -d " " -f 1)" != "${SHA}" ]; then
        echo "Bad SHA, aborting"
        exit 1
    fi
    echo "Untarring"
    tar -xvf "procServ-${VERSION}.tar.gz" -C "${UNTAR_DIR}" --strip-components=1
fi

cd "${UNTAR_DIR}"
if [ -f configure ]; then
    echo "first make already ran"
else
    echo "making configure"
    make
fi
if [ -f Makefile ]; then
    echo "Configure already ran"
else
    echo "Configuring"
    ./configure --enable-access-from-anywhere --disable-doc
fi

if [ -f procServ ]; then
    echo "Make already ran"
else
    echo "Running make"
    make
fi
cd ..

mkdir -p bin

echo "Ensuring bin dir is populated"
cp src/procServ bin
cd bin
for num in {0..7}; do
    if [ ! -L "procmgrd${num}" ]; then
        ln -s procServ "procmgrd${num}"
    fi
done

echo "Done, output is in $(pwd)":
ls -l
