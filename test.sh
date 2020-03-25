#!/bin/bash

set -e
cd `dirname $0`

ARGS="${@:1}"

visit() {
  NAME=$1
  echo "-------------------------------------------------"
  echo "Testing '$NAME'"
  echo "-------------------------------------------------"
  cd $NAME
  pub run test $ARGS
  cd ..
}

visit cryptography
visit kms
visit kms_adapter_cupertino