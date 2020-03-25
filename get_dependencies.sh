#!/bin/sh
set -e
cd `dirname $0`

cd cryptography
pub get
cd ..

cd kms
pub get
cd ..

cd kms_adapter_cupertino
pub get
cd ..