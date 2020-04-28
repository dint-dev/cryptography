#!/bin/bash
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
  pub get $ARGS

  echo ""
  cd ..
}

visit_flutter() {
  NAME=$1
  echo ""
  echo "-------------------------------------------------"
  echo "'$NAME': $ARGS"
  echo "-------------------------------------------------"
  echo ""
  cd $NAME

  # Run the command
  flutter pub get $ARGS

  echo ""
  cd ..
}


visit cryptography
visit kms
visit_flutter kms_flutter
visit noise