#!/bin/bash

set -e
cd `dirname $0`

ARGS="${@:1}"

visit() {
  NAME=$1
  echo "-------------------------------------------------"
  echo "Getting dependencies for '$NAME'"
  echo "-------------------------------------------------"
  cd $NAME
  pub get
  cd ..
}

visit cryptography
visit kms

visit kms_adapter_cupertino