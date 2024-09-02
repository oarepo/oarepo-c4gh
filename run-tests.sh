#!/bin/bash

set -e

OAREPO_VERSION="${OAREPO_VERSION:-12}"

VENV=".venv"

if test -d $VENV ; then
  rm -rf $VENV
fi

python3 -m venv $VENV
. $VENV/bin/activate
pip install -U setuptools pip wheel pytest

#echo "Installing oarepo version $OAREPO_VERSION"
#pip install "oarepo==${OAREPO_VERSION}.*"
pip install -e ".[tests]"

pytest -v -x tests
