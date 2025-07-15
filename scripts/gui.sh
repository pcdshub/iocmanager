#!/usr/bin/bash
THIS_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
cd "${THIS_DIR}/.." || exit
source "${THIS_DIR}"/default_env

export QT_XCB_GL_INTEGRATION=none

"${IOCMAN_PY_BIN}"/python -m iocmanager "$@"
