#!/bin/bash
#
# USAGE
# -----
#
#   ./all.sh pub get
#
#   ./all.sh pub run test
#

set -e
cd `dirname $0`

ARGS="${@:1}"

visit() {
  NAME=$1
  echo ""
  echo "-------------------------------------------------"
  echo "'$NAME': $ARGS"
  echo "-------------------------------------------------"
  echo ""
  cd $NAME

  # Run the command
  $ARGS

  cd ..
  echo ""
}

visit cryptography
visit kms
visit kms_adapter_cupertino